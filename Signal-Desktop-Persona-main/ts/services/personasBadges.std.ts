// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — BADGE CLAIMS. Read this before using them for anything.
//
// ============================================================================
// THESE BADGES ARE NOT CRYPTOGRAPHICALLY ENFORCED. THEY ARE UNVERIFIED CLAIMS.
// ============================================================================
//
// In the real CryptoPersonas design a badge is a credential proved in zero knowledge:
// `MsgUser` carries three badge slots, `standard_badge_request_predicate` proves you
// hold one without revealing who you are, and a moderator grants them through
// `personas-server`. That machinery exists — in `personas-core` (the circuit) and
// `personas-client` (the flow) — but it lives on the AS-A-SERVICE side. The serverless
// `Messenger` that this Desktop build talks to has none of it:
// `grep -ri badge crates/personas-messenger/src/` finds essentially nothing.
//
// What this module provides instead is a DISPLAY-LAYER claim. You pick a label; it
// rides next to your persona post; recipients render it with an explicit "unverified"
// treatment. Anyone can claim anything. A modified client can send any label it likes,
// and nothing anywhere checks it.
//
// This is here to demonstrate the intended UX, not the security property. Every surface
// that shows a badge is required to say so — see PersonaBadgeChip and the status panel.
// Presenting one of these as evidence of a real credential would misrepresent the
// protocol, which for a system whose entire value proposition is "you can verify this
// without trusting anyone" would be a bad trade.
//
// The genuine implementation is specced in PERSONAS_SERVERLESS_TODO.md §2. The blocking
// question is not the circuit (it exists) but the approval authority: with no server,
// who grants a badge, and how does every replica agree that they did?
//
// `.std` so both the renderer and the preload can import it: this is plain data with no
// engine dependency, and the chip that renders it is a `.dom` component.

// The three credentials the real circuit knows about, kept identical to
// `personas-core/src/circuits.rs` (`FACULTY_F`, `STUDENT_F`, `INDUSTRY_F`) so that a
// later real implementation can adopt these labels unchanged. `moderator` is NOT here:
// a moderator badge is the one that would actually gate an action, and offering a fake
// one is exactly the misuse this module is trying to avoid.
export const BADGE_LABELS = ['Faculty', 'Student', 'Industry'] as const;

export type PersonaBadge = (typeof BADGE_LABELS)[number];

export function isPersonaBadge(value: unknown): value is PersonaBadge {
  return (
    typeof value === 'string' &&
    (BADGE_LABELS as ReadonlyArray<string>).includes(value)
  );
}

// The single sentence every badge surface must show. Exported so the wording cannot
// drift between the chip, the picker and the status panel — if a viewer sees a badge
// anywhere, they see this too.
export const BADGE_DISCLAIMER =
  'Unverified claim — badges are not cryptographically enforced in this build. ' +
  'Anyone can claim any badge.';

// Short form, for places with no room for the full sentence (a chip tooltip).
export const BADGE_DISCLAIMER_SHORT = 'Unverified — not enforced';
