// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 6 — MEMBERSHIP, and the auto-join that makes every persona
// action safe to take.
//
// Until now joining was a devtools ritual: `await window.SignalDebug.personasJoin()`,
// once per instance, before any post. Forget it and `emitPostPseudo` throws, the
// composer's persona path silently falls back, and your text goes out as a PLAIN
// message attributed to your real account — the "why is it a normal post from alice?"
// symptom called out in PERSONAS_DEMO.md §8. That is a de-anonymisation footgun
// disguised as a usability bug, and it should not be reachable from the UI at all.
//
// So: every persona action funnels through `ensurePersonaJoined` first. If this
// instance has not joined, we emit + broadcast a join and wait for it before
// proceeding. The join is deliberately ATTRIBUTABLE (the plain PZR2 marker, our real
// account) — the anti-Sybil / ban-evasion property depends on one membership per real
// account, and an anonymous join would let a banned member silently re-join.
//
// Join state is per PROCESS, not persisted: the engine's Member lives in memory and
// the demo backend is ephemeral, so a relaunch genuinely does need a fresh join.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  emitAndSelfIngest,
  isPersonasEngineEnabled,
} from './personasEngine.preload.ts';
import { ensureSealedSenderWarmedUp } from './personasSealedSender.preload.ts';

const log = createLogger('personasMembership');

type JoinState = 'not-joined' | 'joining' | 'joined';

let state: JoinState = 'not-joined';
// The in-flight join, so concurrent actions await one join rather than racing to emit
// several (a second membership for the same account is exactly what we must avoid).
let inFlight: Promise<boolean> | undefined;

export function hasJoinedPersonaGroup(): boolean {
  return state === 'joined';
}

async function sendJoin(conversation: ConversationModel): Promise<boolean> {
  const result = emitAndSelfIngest(engine => engine.emitJoin());
  if (!result) {
    log.error('sendJoin: engine unavailable; cannot join');
    return false;
  }

  // Attributable on purpose: `emitAndSelfIngest` encodes with the plain PZR2 marker,
  // so the group send path leaves it under our real account. Do NOT route this
  // through the phantom.
  await conversation.enqueueMessageForSend(
    { body: result.body, attachments: [] },
    { hideFromTimeline: true }
  );

  log.info(`sendJoin: join broadcast (eh ${result.emitted.eh.slice(0, 12)}…)`);
  return true;
}

// Make sure this instance is a member before a persona action runs. Returns false if
// the engine is unavailable or the join could not be sent — callers MUST treat that
// as "do not proceed" rather than falling back to a plain message.
export async function ensurePersonaJoined(
  conversation: ConversationModel
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  if (state === 'joined') {
    return true;
  }
  if (inFlight) {
    return inFlight;
  }

  state = 'joining';
  inFlight = (async () => {
    try {
      // Warm sealed sender BEFORE the join. Every persona action funnels through
      // here, so this is the one place that guarantees the group can be sealed to
      // before anything anonymous is sent. The warm-up is an ordinary attributable
      // message — which is precisely what teaches peers our profile key.
      const readiness = await ensureSealedSenderWarmedUp(conversation);
      if (!readiness.ready) {
        // Not fatal: the join itself is attributable anyway, and peers may still
        // reply. But it is worth saying loudly, because a persona POST sent while
        // this is false is the de-anonymisation case.
        log.warn(
          `ensurePersonaJoined: sealed sender not ready — awaiting a reply from ${readiness.missing.join(', ')}`
        );
      }

      const ok = await sendJoin(conversation);
      state = ok ? 'joined' : 'not-joined';
      return ok;
    } catch (error) {
      log.error(`ensurePersonaJoined: failed: ${toLogFormat(error)}`);
      state = 'not-joined';
      return false;
    } finally {
      inFlight = undefined;
    }
  })();

  return inFlight;
}
