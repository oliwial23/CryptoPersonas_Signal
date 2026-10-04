// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — AUTHORSHIP CLAIMS, as a UI mockup.
//
// ============================================================================
// THIS IS NOT A PROOF. IT IS AN UNVERIFIED ASSERTION, LIKE A BADGE.
// ============================================================================
//
// The real feature: prove that one member owns two pseudonyms, without revealing which
// member. `authorship_pred` exists in `personas-core/src/circuits.rs` and — unusually
// for these gaps — its Merkle proving key is ALREADY GENERATED and already ships in the
// ~51 MB bundle. What is missing is small: `MemberKeys` does not extract the key, there
// is no `Member::authorship()` to build the statement, and there is no napi binding.
// PERSONAS_SERVERLESS_TODO.md section 1 estimates ~60 lines of Rust.
//
// Why it is a mockup and not the real thing: that Rust cannot be compiled or tested from
// here, and the last fifteen lines of Rust added to this project (`get_reputation`)
// compiled cleanly and then SIGKILLed the render process — see PERSONAS_DEMO.md section
// 8.0. Shipping unverifiable Rust into a working demo is a bad trade, so this
// demonstrates the interaction and states plainly that it proves nothing.
//
// What it actually does: sends "~alpha and ~beta are the same person" as a claim message.
// Anyone can claim any two petnames, including two that are not theirs. A recipient has
// no way to check it.
//
// Sent ATTRIBUTABLY rather than over the phantom. That is deliberate: the claimant is
// voluntarily linking two of their own personas, so there is nothing left to conceal
// about who is speaking — and routing it anonymously would imply the link is protected
// when it is not.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { encodeAuthorshipClaim } from './personasCarriage.std.ts';
import { isPersonasEngineEnabled } from './personasEngine.preload.ts';

const log = createLogger('personasAuthorship');

// Re-exported so preload-side callers have one import, while the wording itself lives
// in the `.std` module the renderer can reach.
export { AUTHORSHIP_DISCLAIMER } from './personasAuthorship.std.ts';

export async function sendAuthorshipClaim(
  conversation: ConversationModel,
  first: string,
  second: string
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  if (!first || !second || first === second) {
    // Claiming a persona is the same as itself is vacuous; refuse rather than send
    // something that looks like a statement but says nothing.
    log.warn('sendAuthorshipClaim: refusing an empty or self-referential claim');
    return false;
  }
  try {
    // Same split the poll path uses: `personaCarriageBody` is what goes on the wire,
    // while `personaAuthorship` is what the bubble renders from. Sending it hidden
    // would mean the claimant is the only person who cannot see their own claim.
    await conversation.enqueueMessageForSend(
      {
        body: undefined,
        attachments: [],
        personaCarriageBody: encodeAuthorshipClaim({ first, second }),
        personaAuthorship: { first, second },
      },
      {}
    );
    log.info(`sendAuthorshipClaim: claimed ${first} = ${second}`);
    return true;
  } catch (error) {
    log.error(`sendAuthorshipClaim failed: ${toLogFormat(error)}`);
    return false;
  }
}
