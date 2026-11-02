// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — EXPERIMENT LOG, for end-to-end timings across real app windows.
//
// Off unless the app is started with PERSONAS_BENCH_LOG=<file>. Then every instance (the
// main window and its extra members, which inherit the variable) appends one JSON line
// per event to that file:
//
//   emit     a member produced something: { op, group, key, startMs, endMs, proveMs,
//            selfIngestMs, bytes } — `startMs` is when the action began (before proving),
//            `endMs` when it was ready to hand to Signal
//   receive  a member took a record in: { group, key, kind, status, receivedMs, doneMs,
//            ingestMs } — `ingestMs` is the engine's verify + order + apply
//   verify   a member checked a standalone proof (authorship, badge): { op, key, ms, ok }
//   settle   a barrier invoked callbacks: { group, barrier, invoked, invokeMs,
//            epochUpdateMs }
//
// `key` joins a sender's emit with every receiver's receive: the record's envelope hash,
// or a hash of a standalone proof. `deploy/play/bench/e2e.py` turns the file into
// per-operation end-to-end latencies (receiver done − sender start). Timestamps are
// wall-clock milliseconds, so instances must share a clock: several windows on one Mac
// do; across machines, sync them (NTP) and expect that error in the result.
//
// Logging is a synchronous append of one short line, only when enabled.

import { appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const path = process.env.PERSONAS_BENCH_LOG?.trim() || undefined;
const instance = process.env.PERSONAS_PROFILE || 'main';

export function isBenchLogEnabled(): boolean {
  return path != null;
}

/** High-resolution wall-clock milliseconds. */
export function benchNowMs(): number {
  return performance.timeOrigin + performance.now();
}

/** The join key for a standalone proof (not a record). */
export function benchProofKey(proof: ArrayBufferView): string {
  const bytes = Buffer.from(proof.buffer, proof.byteOffset, proof.byteLength);
  return createHash('sha256').update(bytes).digest('hex').slice(0, 32);
}

export function benchLog(event: Record<string, unknown>): void {
  if (!path) {
    return;
  }
  try {
    appendFileSync(path, `${JSON.stringify({ ...event, instance })}\n`);
  } catch {
    // An experiment log must never break the app.
  }
}
