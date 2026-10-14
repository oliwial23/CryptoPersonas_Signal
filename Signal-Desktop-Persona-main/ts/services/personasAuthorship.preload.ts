// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — AUTHORSHIP PROOFS: "these two pseudonyms are the same author."
//
// A REAL PROOF, and every sentence of this header used to say otherwise. It was a
// mockup — two petname strings in a message body, checkable by nobody — and the
// comment that stood here described that honestly. `Member::authorship()` and the napi
// binding now exist, so the claim is a Groth16 proof over `authorship_pred` binding both
// pseudonyms to one secret key, verified on receipt and DROPPED if it fails.
//
// Kept as history rather than deleted, because the shape of the old version explains two
// things about the current one:
//
//   * WHY THE NAMES COME FROM THE VERIFIER. The mockup took them from the sender's
//     input, which is what made it forgeable. `verifyPersonaAuthorship` returns them
//     from the proof's public inputs, and that is the only place any surface reads them.
//   * WHY IT NOW RIDES THE PHANTOM. The mockup was sent attributably, on the reasoning
//     that "the claimant is voluntarily linking two of their own personas, so there is
//     nothing left to conceal". True of an assertion; false of a proof. The proof shows
//     the two pseudonyms share an author WITHOUT revealing who, so an attributable
//     envelope answers precisely the question the proof is built to leave open.
//
// Compare personasBadgeProof.preload.ts, which is the same construction for badges.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  isPersonasEngineEnabled,
  composePersonaAuthorship,
  verifyPersonaAuthorship,
} from './personasEngine.preload.ts';

const log = createLogger('personasAuthorship');

// Re-exported so preload-side callers have one import, while the wording itself lives
// in the `.std` module the renderer can reach.
// Re-exported so preload-side callers have one import, while the wording lives in the
// `.std` module the renderer can reach. AUTHORSHIP_DISCLAIMER is gone: the claim is a
// verified proof now, and the disclaimer was deleted in the change that made it false.
export {
  AUTHORSHIP_EXPLANATION,
  AUTHORSHIP_VERIFIED_LABEL,
} from './personasAuthorship.std.ts';

export async function sendAuthorshipClaim(
  conversation: ConversationModel,
  contextA: number,
  contextB: number
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  if (!Number.isFinite(contextA) || !Number.isFinite(contextB)) {
    log.warn('sendAuthorshipClaim: refusing a non-numeric context');
    return false;
  }
  if (contextA === contextB) {
    // A pseudonym is trivially itself: the proof would verify and assert nothing.
    log.warn('sendAuthorshipClaim: refusing a self-referential claim');
    return false;
  }
  try {
    // NOW A REAL PROOF. Previously this shipped two petname strings and the bubble
    // simply repeated them, which is why the claim carried a permanent disclaimer.
    // `composePersonaAuthorship` produces a Groth16 proof over `authorship_pred`
    // binding both pseudonyms to one secret key.
    const claim = composePersonaAuthorship(contextA, contextB);
    if (!claim) {
      log.error('sendAuthorshipClaim: could not produce the proof');
      return false;
    }

    // Verify OUR OWN proof before sending, and render from the verifier's output.
    //
    // Two reasons. It catches a malformed or mis-ordered proof here rather than at
    // every recipient. And it means the sender's own bubble is built from the same
    // source of truth as everyone else's — the proof's public inputs — so there is no
    // path anywhere that renders a name the proof does not vouch for.
    const verified = verifyPersonaAuthorship(claim.proof);
    if (!verified) {
      log.error(
        'sendAuthorshipClaim: our own proof failed to verify; refusing to send it'
      );
      return false;
    }

    await conversation.enqueueMessageForSend(
      {
        body: undefined,
        attachments: [],
        personaCarriageBody: claim.body,
        // Anonymous on our own copy too, so the sender sees the same bubble everyone
        // else does. Showing "carol proved authorship" locally while every recipient
        // sees "Anonymous" would leave the one person who most needs to understand the
        // privacy property with the one view that contradicts it.
        personaAnonymous: true,
        personaAuthorship: {
          first: verified.first,
          second: verified.second,
          verified: true,
        },
      },
      {}
    );
    log.info(
      `sendAuthorshipClaim: proved ${verified.first} = ${verified.second}`
    );
    return true;
  } catch (error) {
    log.error(`sendAuthorshipClaim failed: ${toLogFormat(error)}`);
    return false;
  }
}
