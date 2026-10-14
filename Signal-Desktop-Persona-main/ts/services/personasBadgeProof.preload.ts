// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — CLAIM BADGE: proving badge possession in zero knowledge.
//
// This is the third and last thing a badge can be in this build, and the distinction
// between the three is the entire point of this file:
//
//   1. a REQUEST   — "please give me Faculty". Grants nothing (personasBadgeFlow).
//   2. a LABEL     — the `b` field on a post. A string the sender typed. The client now
//                    refuses to attach one it does not hold, but no RECIPIENT checks it,
//                    so against a modified client it is worth nothing.
//   3. a PROOF     — this. A Groth16 proof over `badge_pred` that the sender's own zk
//                    object contains the badge. Unforgeable, and checked on receipt.
//
// Only (3) is evidence. A proof cannot be produced without the badge actually being in
// the member's object, which happens exactly one way: an admin approved the request, the
// replica invoked the callback at a settlement barrier, and the member scanned it in.
//
// WHAT IT DOES NOT REVEAL, and this is why it is worth having rather than just trusting
// the label: the proof says "the holder of some member object in this group has a
// Faculty badge". It does not say which member, and it is carried over the shared
// phantom so the envelope does not say either. That is the property the paper is about.
//
// A proof that fails verification is DROPPED, never rendered as "unverified" — same rule
// as authorship. An unverifiable badge proof has no legitimate sender, so showing it at
// all would only give a forger a surface to write on.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  composePersonaBadgeProof,
  isPersonasEngineEnabled,
  verifyPersonaBadgeProof,
} from './personasEngine.preload.ts';
import { ensurePersonaJoined } from './personasMembership.preload.ts';

const log = createLogger('personasBadgeProof');

export type BadgeProofResult =
  | { ok: true; badge: string }
  | { ok: false; reason: string };

/**
 * Prove that we hold `badge`, and show the proof to the group.
 *
 * Returns the badge name the PROOF vouches for, not the one that was asked for. They
 * are the same in practice, but reading it back from the verifier is what guarantees the
 * bubble cannot claim something the proof does not establish.
 */
export async function sendBadgeProof(
  conversation: ConversationModel,
  badge: string
): Promise<BadgeProofResult> {
  if (!isPersonasEngineEnabled()) {
    return { ok: false, reason: 'the personas engine is not enabled' };
  }
  try {
    if (!(await ensurePersonaJoined(conversation))) {
      return {
        ok: false,
        reason: 'could not join the bulletin — try again in a moment',
      };
    }

    const claim = composePersonaBadgeProof(badge);
    if (!claim) {
      // The expected failure, and worth wording precisely: the proof is not "broken",
      // it is UNSATISFIABLE, because the witness does not exist. That is the security
      // property doing its job, so the message says what to do about it rather than
      // implying something went wrong.
      return {
        ok: false,
        reason: `you do not hold ${badge} in your object yet — an admin must approve it and you must then Scan now`,
      };
    }

    // Verify our OWN proof before sending it, and render from the verifier's answer.
    // Catches a malformed proof here instead of at every recipient, and guarantees the
    // sender's bubble is built from the same source of truth as everyone else's.
    const verified = verifyPersonaBadgeProof(claim.proof);
    if (!verified) {
      log.error(
        'sendBadgeProof: our own proof failed to verify; refusing to send it'
      );
      return {
        ok: false,
        reason: 'the proof did not verify locally, so it was not sent',
      };
    }
    if (verified !== badge) {
      // Should be impossible. If it ever happens, the proof proves something other than
      // what was asked for, and sending it would publish a true-but-wrong statement.
      log.error(
        `sendBadgeProof: asked to prove ${badge} but the proof verifies as ${verified}; refusing`
      );
      return {
        ok: false,
        reason: `the proof verifies as ${verified}, not ${badge}`,
      };
    }

    await conversation.enqueueMessageForSend({
      body: undefined,
      attachments: [],
      personaCarriageBody: claim.body,
      // Anonymous everywhere, including on our own copy. A sender who saw their own
      // name on a bubble everyone else sees as "Anonymous" would draw exactly the wrong
      // conclusion about what they just published.
      personaAnonymous: true,
      personaBadgeProof: { badge: verified, verified: true },
    });
    log.info(`sendBadgeProof: proved possession of ${verified}`);
    return { ok: true, badge: verified };
  } catch (error) {
    log.error(`sendBadgeProof failed: ${toLogFormat(error)}`);
    return { ok: false, reason: String(error) };
  }
}
