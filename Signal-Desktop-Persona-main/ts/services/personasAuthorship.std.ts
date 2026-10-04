// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The wording for an UNVERIFIED authorship claim, in a `.std` module so the bubble that
// renders it (a `.dom` component) can import it without pulling the native ZK addon into
// the renderer bundle — the same reason personasLimitations.std.ts exists.
//
// One definition, so the sender's menu and the recipient's bubble cannot drift apart.

export const AUTHORSHIP_DISCLAIMER =
  'Unverified claim — this build cannot prove authorship. The claimant asserts these ' +
  'two personas are theirs; nothing checks it, and anyone can claim any pair.';
