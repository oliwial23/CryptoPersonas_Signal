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
import { pendingBadgeRequests } from './personasBadgeFlow.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  getPersonasEngine,
  isPersonasEngineEnabled,
} from './personasEngine.preload.ts';
import { hasJoinedPersonaGroup } from './personasMembership.preload.ts';
import { getSealedSenderReadiness } from './personasSealedSender.preload.ts';
import { listTopics } from './personasTopics.preload.ts';
import { isAutoScanEnabled } from './personasFlags.preload.ts';

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
   * Whether scans are emitted automatically. Off by default: a scan is a synchronous
   * Groth16 proof and a wire record, so it runs on demand rather than on a timer. With
   * it off a revoked member's own object is only marked banned once they scan, so this
   * is worth being able to see.
   */
  autoScan: boolean;
  /** A callback sweep is unfinished. While true, posting/rating/voting are REFUSED. */
  /**
   * Banned in THIS group. Undefined while unknown (observer, or an addon without the
   * binding) so the UI can distinguish "not banned" from "cannot tell" — reporting an
   * unknown as "No" would be the reassuring-but-wrong answer this panel exists to avoid.
   */
  banned?: boolean;
  /**
   * Can this build PROVE and VERIFY authorship in zero knowledge? Derived from the
   * addon's bindings rather than hardcoded, so an older `.node` reports false instead
   * of the panel claiming a capability the running engine does not have.
   */
  authorshipZk: boolean;
  /**
   * Badges genuinely held in this member's zk object, as opposed to the unverified
   * label the composer attaches to a post. The gap between these two is the whole
   * point of the badge work: today the composer can claim any label, and this list is
   * what a real credential would look like.
   */
  heldBadges: ReadonlyArray<string>;
  /** Badge requests awaiting approval. Only actionable by a Signal group admin. */
  pendingBadgeRequests: ReadonlyArray<{ eh: string; slot: number; name: string }>;
  scanStuck: boolean;
  /** Callbacks outstanding mid-sweep; scanning until zero is the way out. */
  outstandingCallbacks: number;
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
    isSignalAdmin: conversation?.areWeAdmin() ?? false,
    autoScan: isAutoScanEnabled(),
    authorshipZk: false,
    heldBadges: [],
    pendingBadgeRequests: [],
    scanStuck: false,
    outstandingCallbacks: 0,
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
      // Log the RAW value and its type. The status row shows "—" for anything nullish,
      // which collapses three very different situations into one appearance: the method
      // is absent from the addon, the method exists and returns null/None, or it returns
      // a real number that something downstream drops. The shipped .node does export
      // `getReputation`, so "—" on screen means one of the latter two — and only the
      // raw value distinguishes them.
      // An unfinished sweep used to be invisible AND fatal: the callbacks crate
      // asserts rather than erroring, so the next post aborted the renderer with
      // nothing in the JS logs. The addon now refuses those calls, so this has to be
      // SHOWN — a refusal nobody can see is almost as bad as a crash.
      if (typeof engine.getBadges === 'function') {
        status.heldBadges = engine.getBadges();
      }

      status.pendingBadgeRequests = pendingBadgeRequests();

      status.authorshipZk =
        typeof engine.emitAuthorship === 'function' &&
        typeof engine.verifyAuthorship === 'function';

      if (typeof engine.isBanned === 'function') {
        status.banned = engine.isBanned();
      }

      if (typeof engine.isScanning === 'function') {
        status.scanStuck = engine.isScanning();
        status.outstandingCallbacks =
          typeof engine.outstandingCallbacks === 'function'
            ? engine.outstandingCallbacks()
            : 0;
        if (status.scanStuck) {
          log.warn(
            `personas: callback sweep unfinished (${status.outstandingCallbacks} ` +
            'outstanding) — posting is refused until it completes'
          );
        }
      }

      // KILL SWITCH, independent of the addon. The status panel polls this every 2s
      // while open, so if `getReputation` is what kills the renderer, the panel becomes
      // unusable — and the panel is where every other diagnostic lives. Setting
      // PERSONAS_SKIP_REPUTATION=1 keeps the panel working while the Rust side is being
      // bisected, and separates "opening the panel crashes" from "reading reputation
      // crashes" without a rebuild.
      if (process.env.PERSONAS_SKIP_REPUTATION === '1') {
        log.info('personas: getReputation skipped (PERSONAS_SKIP_REPUTATION=1)');
        status.reputation = undefined;
      } else if (typeof engine.getReputation === 'function') {
        let raw: unknown;
        try {
          raw = engine.getReputation();
        } catch (error) {
          // A throwing read must not take out the whole status panel.
          log.error(`getPersonaStatus: getReputation threw: ${toLogFormat(error)}`);
          raw = undefined;
        }
        log.info(
          `personas: getReputation -> ${JSON.stringify(raw) ?? 'undefined'} (typeof ${typeof raw})`
        );
        status.reputation = typeof raw === 'number' ? raw : undefined;
      } else {
        log.warn(
          'personas: this .node does not export getReputation; reputation will read "—"'
        );
        status.reputation = undefined;
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
