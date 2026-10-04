// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — the STATUS SNAPSHOT behind the status panel.
//
// Everything here was previously visible only by typing `window.SignalDebug.personas*`
// into devtools. That is fine for the person who wrote it and useless for anyone else in
// the room, and several of these values are the difference between "the demo is working"
// and "the demo looks like it is working":
//
//   * sealed-sender readiness — if this is false, a persona post is not protected.
//   * join state — un-joined, persona actions are refused.
//   * replica fingerprint — if two instances differ, they have diverged and every
//     tally, flag and ban is unreliable on at least one of them.
//   * barrier — if this is not advancing, no ban can ever settle.
//
// The panel deliberately reports what IS, including when that is unflattering. A status
// display that only ever shows green is worth nothing.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  getPersonasEngine,
  isPersonasEngineEnabled,
} from './personasEngine.preload.ts';
import { hasJoinedPersonaGroup } from './personasMembership.preload.ts';
import { getSealedSenderReadiness } from './personasSealedSender.preload.ts';
import { listTopics } from './personasTopics.preload.ts';
import {
  getPersonaProofStatus,
  type PersonaProofStatus,
} from './personasProofLock.preload.ts';

export { KNOWN_LIMITATIONS } from './personasLimitations.std.ts';

const log = createLogger('personasStatus');

export type PersonaStatus = {
  /** False when the demo is not enabled at all (normal builds). */
  enabled: boolean;
  joined: boolean;
  /** Sealed sender: can every group member be sealed to yet? */
  sealedSenderReady: boolean;
  /** Members still missing a profile key, by display name. */
  sealedSenderMissing: ReadonlyArray<string>;
  /** The replica's current settlement barrier, or undefined if unavailable. */
  barrier?: number;
  /**
   * The three Merkle roots as hex. Compare across instances: identical means the
   * replicas agree; different means they have diverged.
   */
  fingerprint?: string;
  /** Topics this instance knows, with their contexts. */
  topics: ReadonlyArray<{ name: string; context: number }>;
  /** Engine poll status lines, verbatim. */
  polls: ReadonlyArray<string>;
  /** How many records this replica currently holds. */
  recordCount: number;
  /**
   * Our own reputation, or undefined if unavailable (observer, not joined, or an
   * addon built before `getReputation` existed).
   */
  reputation?: number;
  proof: PersonaProofStatus;
  /**
   * Whether we hold Signal's GroupV2 ADMINISTRATOR role in this conversation.
   *
   * REAL for Signal's own group operations — the storage-service validates signed
   * group-change actions against the member's role. NOT enforcement for persona
   * actions: those are ordinary message bodies the server never inspects, so any
   * check the client makes here can be ignored by a modified client. It gates only
   * ATTRIBUTABLE actions (topic creation); anonymous ones are left ungated, because
   * checking who performed them would de-anonymise them.
   */
  isSignalAdmin: boolean;
  /**
   * True when the timeline shows persona messages the replica has never heard of —
   * i.e. protocol state was lost. The bulletin lives only in memory, so a restart
   * forgets every record while the CHAT history survives, leaving a UI that looks
   * populated on top of an empty replica. Worth saying out loud, because in that
   * state tallies read as zero and bans cannot settle.
   */
  stateLost: boolean;
};

export function getPersonaStatus(
  conversation: ConversationModel | undefined,
  // How many persona messages the UI is currently showing. Compared against the
  // replica's own record count to detect state loss (see `stateLost`).
  uiPersonaMessageCount = 0
): PersonaStatus {
  const enabled = isPersonasEngineEnabled();
  const readiness = conversation
    ? getSealedSenderReadiness(conversation)
    : { ready: false, missing: [], total: 0 };

  const status: PersonaStatus = {
    enabled,
    joined: hasJoinedPersonaGroup(),
    sealedSenderReady: readiness.ready,
    sealedSenderMissing: readiness.missing,
    topics: listTopics(),
    polls: [],
    recordCount: 0,
    proof: getPersonaProofStatus(),
    isSignalAdmin: conversation?.areWeAdmin() ?? false,
    stateLost: false,
  };

  if (!enabled) {
    return status;
  }

  // Engine reads are best-effort: a status panel must never be the thing that breaks
  // the app, and an unavailable engine is itself worth reporting (as undefined).
  try {
    const engine = getPersonasEngine();
    if (engine) {
      status.barrier = engine.currentBarrier();
      status.fingerprint = engine.fingerprint();
      status.polls = engine.renderPolls();
      status.recordCount = engine.log().length;
      // Guarded: a Desktop build can outrun the native addon, and an older .node
      // without this method must degrade to "unavailable" rather than throwing
      // inside the status panel.
      if (typeof engine.getReputation === 'function') {
        const reputation = Number(engine.getReputation());
        if (Number.isSafeInteger(reputation)) {
          status.reputation = reputation;
        }
      }
      // The chat outlives the replica, so a populated timeline over an empty replica
      // is the signature of a restart having dropped the protocol state.
      status.stateLost = uiPersonaMessageCount > 0 && status.recordCount === 0;
    }
  } catch (error) {
    log.error(`getPersonaStatus: engine read failed: ${toLogFormat(error)}`);
  }

  return status;
}
