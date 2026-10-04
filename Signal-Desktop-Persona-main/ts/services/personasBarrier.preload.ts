// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 6 — the SHARED BARRIER SCHEDULE.
//
// This closes the two "for now" seams left by Phases 3-5: both the emit and the
// ingest side passed `0` to `Engine.ingest`, i.e. the LOCAL-barrier cadence, where a
// replica only advances when someone calls `barrier()` by hand. That is exactly what
// `packages/personas-engine/test/converge.mjs` does — it steps both replicas in
// lockstep — and it is fine there because one process owns both. It does NOT work
// across N Desktop instances:
//
//   * Nothing ever called `barrier()` in the app, so no settlement barrier was ever
//     crossed, so a ban poll could never settle and a revoked persona's posts could
//     never flag. Ban was structurally unreachable outside the test.
//   * Even if each instance called `barrier()` on a timer, they would cross at
//     different points in the record stream and their replica roots would diverge.
//
// The engine already has the fix: construct it with `heartbeatAnchorMs` +
// `heartbeatPeriodMs` and every replica buckets an ingest onto a barrier derived from
// the record's SERVICE timestamp — the server's clock, identical for every recipient
// — instead of local arrival order. `tick(nowMs)` then advances the barrier that the
// same shared schedule says wall-clock has reached, so settlement happens on time
// even in a silent group.
//
// The anchor must be byte-identical across members, so it is shared the same way the
// phantom bundle is: one file in the roster dir, published with an exclusive link so
// a boot race converges on a single winner.

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  linkSync,
  unlinkSync,
  statSync,
  utimesSync,
} from 'node:fs';
import { join } from 'node:path';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { getRosterDir } from '../textsecure/personaRoster.preload.ts';

const log = createLogger('personasBarrier');

const SCHEDULE_FILE = 'personas-heartbeat.json';

// How long one settlement barrier lasts. A poll needs `settlementBarriers` (default
// 3) of these to close, so ~30s from opening a ban poll to the ban biting — brisk
// enough to demo live, slow enough that a vote emitted on another instance (Groth16
// proof-gen is seconds) still lands in the right bucket.
const DEFAULT_PERIOD_MS = 10_000;

// How often we nudge the replica forward. Must be well under the period so a barrier
// is crossed promptly once wall-clock passes it.
const TICK_INTERVAL_MS = 1_000;

// How long the schedule file may go untouched before we treat the session that minted
// it as OVER and mint a fresh anchor.
//
// This exists because the anchor is not just a convergence detail — it sets how much
// work the replica does. `Replica::rebuild()` loops `for b in 0..=current_barrier`, and
// `current_barrier` is `(now - anchorMs) / periodMs`. So the cost of every barrier
// crossing grows with WALL-CLOCK TIME SINCE THE ANCHOR WAS FIRST MINTED, forever:
//
//     anchor age    barriers    iterations per rebuild, every `periodMs`
//     1 hour             360    fine
//     1 day            8,640    noticeable
//     1 week          60,480    kills the render process
//
// The anchor lives in the roster dir (default `/tmp/personas-roster`), which survives
// both `--reset` and app restarts, so it kept ageing across days of demo runs while
// each rebuild got steadily more expensive. That is an OOM on a timer, and it presents
// as `Render process is gone / Exit Code: 9` — a SIGKILL with no catchable error.
//
// Re-minting has to be done carefully: two members on different anchors bucket records
// differently and their replicas DIVERGE, which is worse than being slow because it is
// silent. So staleness is judged by LIVENESS, not by age: every running instance
// touches the file on its ticker, so a file untouched for this long means no instance
// is currently up and re-anchoring can hurt nobody.
const LIVENESS_WINDOW_MS = 5 * 60_000;

// How often a running instance touches the schedule file to say "a session is live".
// Must be comfortably under LIVENESS_WINDOW_MS.
const TOUCH_INTERVAL_MS = 60_000;

export type BarrierSchedule = {
  anchorMs: number;
  periodMs: number;
};

let schedule: BarrierSchedule | undefined;
let loadFailed = false;

// True when the anchor file has not been touched inside the liveness window, i.e. the
// session that minted it is gone. A file we cannot stat is treated as live: refusing to
// re-anchor risks slowness, wrongly re-anchoring risks silent divergence.
function isAbandoned(path: string): boolean {
  try {
    return Date.now() - statSync(path).mtimeMs > LIVENESS_WINDOW_MS;
  } catch {
    return false;
  }
}

function periodFromEnv(): number {
  const raw = Number(process.env.PERSONAS_BARRIER_PERIOD_MS);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_PERIOD_MS;
}

// The schedule every member of this demo group shares, or undefined when there is no
// roster dir (no roster dir => a single lone instance => nothing to agree with, and
// the caller falls back to the local-barrier cadence).
//
// Synchronous on purpose: the engine is constructed lazily and synchronously, and it
// needs the schedule at construction time.
export function getBarrierSchedule(): BarrierSchedule | undefined {
  if (schedule || loadFailed) {
    return schedule;
  }
  const dir = getRosterDir();
  if (!dir) {
    return undefined;
  }

  const path = join(dir, SCHEDULE_FILE);
  try {
    mkdirSync(dir, { recursive: true });

    try {
      const parsed = JSON.parse(readFileSync(path, 'utf8')) as BarrierSchedule;
      if (
        !Number.isFinite(parsed?.anchorMs) ||
        !Number.isFinite(parsed?.periodMs) ||
        parsed.periodMs <= 0
      ) {
        throw new Error('malformed schedule');
      }
      // An anchor from a session that has ended is not merely stale, it is expensive:
      // the replica would start at barrier (now - anchor)/period and rebuild that many
      // steps on every crossing. Drop it and fall through to minting a fresh one.
      if (isAbandoned(path)) {
        const barriers = Math.floor(
          (Date.now() - parsed.anchorMs) / parsed.periodMs
        );
        log.warn(
          `getBarrierSchedule: schedule at ${path} is abandoned (untouched for ` +
            `>${LIVENESS_WINDOW_MS}ms) and would start the replica at barrier ` +
            `${barriers}; re-anchoring. If other instances ARE running, stop them ` +
            'and start them again so everyone shares one anchor.'
        );
        unlinkSync(path);
        throw new Error('abandoned schedule');
      }
      schedule = { anchorMs: parsed.anchorMs, periodMs: parsed.periodMs };
      log.info(
        `getBarrierSchedule: loaded shared schedule (anchor ${schedule.anchorMs}, ` +
          `period ${schedule.periodMs}ms, currently at barrier ` +
          `${Math.floor((Date.now() - schedule.anchorMs) / schedule.periodMs)})`
      );
      return schedule;
    } catch {
      // Not published yet — we are (probably) the first instance up. Mint it and
      // publish with an exclusive link; on EEXIST another instance beat us and we
      // adopt theirs, so every member ends up on one schedule.
    }

    const minted: BarrierSchedule = {
      anchorMs: Date.now(),
      periodMs: periodFromEnv(),
    };
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(minted, null, 2), 'utf8');
    try {
      linkSync(tmp, path);
      schedule = minted;
      log.info(
        `getBarrierSchedule: published new schedule (anchor ${minted.anchorMs}, period ${minted.periodMs}ms)`
      );
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
        const parsed = JSON.parse(readFileSync(path, 'utf8')) as BarrierSchedule;
        schedule = { anchorMs: parsed.anchorMs, periodMs: parsed.periodMs };
        log.info('getBarrierSchedule: lost publish race; adopted existing schedule');
      } else {
        throw error;
      }
    } finally {
      try {
        unlinkSync(tmp);
      } catch {
        // best effort
      }
    }

    return schedule;
  } catch (error) {
    loadFailed = true;
    log.error(`getBarrierSchedule: failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// True when we are on the shared schedule, so callers know a real service timestamp
// is meaningful to `ingest` (rather than the local-barrier `0`).
function isSharedBarrierScheduleActive(): boolean {
  return getBarrierSchedule() != null;
}

// The timestamp to hand `Engine.ingest` for a record. On the shared schedule this is
// the SERVICE timestamp — the server's own clock, which every recipient sees
// identically, so all replicas bucket the record onto the same barrier regardless of
// local arrival order. Off the schedule it is `0`, the local-barrier cadence.
//
// A missing/zero service timestamp (e.g. our own just-emitted record, which never
// went to the server) falls back to local wall-clock: close enough to the service
// clock in a loopback demo to land in the same bucket.
export function ingestTimestampFor(serviceTimestampMs?: number | null): number {
  if (!isSharedBarrierScheduleActive()) {
    return 0;
  }
  if (serviceTimestampMs != null && serviceTimestampMs > 0) {
    return serviceTimestampMs;
  }
  return Date.now();
}

let tickInterval: NodeJS.Timeout | undefined;
let lastBarrier = -1;

// Start nudging the replica along the shared schedule. Without this a barrier is
// only crossed when a record happens to arrive in a later bucket, so a ban poll in a
// quiet group would never settle. `tick` is idempotent per barrier — it advances TO
// the barrier the schedule says `nowMs` reached and returns it.
//
// `advance` is injected so this module stays free of an engine import (and so the
// caller decides what "the engine" is); `background.preload.ts` wires it up.
export function startBarrierTicker(advance: (nowMs: number) => number | undefined): void {
  if (tickInterval || !isSharedBarrierScheduleActive()) {
    return;
  }
  log.info(`startBarrierTicker: ticking every ${TICK_INTERVAL_MS}ms`);
  tickInterval = setInterval(() => {
    try {
      const barrier = advance(Date.now());
      if (barrier != null && barrier !== lastBarrier) {
        lastBarrier = barrier;
        log.info(`startBarrierTicker: crossed to barrier ${barrier}`);
      }
    } catch (error) {
      log.error(`startBarrierTicker: tick failed: ${toLogFormat(error)}`);
    }
  }, TICK_INTERVAL_MS);

  startLivenessTouch();
}

let touchInterval: NodeJS.Timeout | undefined;

// Say "a session is live" by touching the schedule file's mtime, so a LATER instance
// does not decide the anchor is abandoned and re-mint it underneath us — which would
// put two members on different anchors and diverge their replicas silently.
//
// mtime rather than a lockfile or a pid: a lock has to be released, and the failure
// mode of a lock left behind by a crashed instance is exactly the state this is meant
// to escape. An mtime needs no cleanup and expires on its own.
function startLivenessTouch(): void {
  if (touchInterval) {
    return;
  }
  const dir = getRosterDir();
  if (!dir) {
    return;
  }
  const path = join(dir, SCHEDULE_FILE);

  const touch = () => {
    try {
      const now = new Date();
      utimesSync(path, now, now);
    } catch (error) {
      // The file can legitimately be missing (another instance re-anchoring). This is
      // advisory, so never let it disturb the ticker.
      log.warn(`startLivenessTouch: touch failed: ${toLogFormat(error)}`);
    }
  };

  touch();
  touchInterval = setInterval(touch, TOUCH_INTERVAL_MS);
}
