// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Wording for a ZK-PROVED authorship claim, in a `.std` module so the bubble that
// renders it (a `.dom` component) can import it without pulling the native ZK addon
// into the renderer bundle — the same reason personasLimitations.std.ts exists.
//
// AUTHORSHIP_DISCLAIMER IS GONE, deliberately, in the same change that made it false.
// It read:
//
//   "Unverified claim — this build cannot prove authorship. The claimant asserts these
//    two personas are theirs; nothing checks it, and anyone can claim any pair."
//
// Every clause of that is now wrong. The claim carries a Groth16 proof over
// `authorship_pred`; both pseudonyms are derived from the claimant's secret key inside
// the circuit; recipients verify before rendering and DROP a proof that fails. Leaving
// a disclaimer in place after it stopped being true would be its own kind of lie — and
// a worse one than an honest caveat, because it would train people to ignore the ones
// that are still accurate.

/** Shown in the composer's claim dialog, before anything is sent. */
export const AUTHORSHIP_EXPLANATION =
  'This proves in zero knowledge that both personas belong to the same author — you. ' +
  'The proof reveals nothing about your account or your other personas, and anyone in ' +
  'the group can check it. It cannot be retracted once sent, and it permanently links ' +
  'these two personas to each other for everyone who sees it.';

/** Shown on the rendered bubble, beside the two names the proof vouches for. */
export const AUTHORSHIP_VERIFIED_LABEL =
  'Verified by zero-knowledge proof. These two personas provably share one author; ' +
  'the names shown are read from the proof itself, not from the message.';
