// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

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
