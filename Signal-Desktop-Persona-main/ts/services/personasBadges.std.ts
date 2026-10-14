// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — BADGE LABELS, and precisely how much they are worth.
//
// A badge now has a real grant path. `Record::BadgeRequest` files a callback, an admin's
// `Record::BadgeApprove` marks the ticket, the replica invokes BADGE{1,2,3}_FLAG at the
// settlement barrier, and the requester's next scan writes the badge into their own
// `MsgUser` object. `badge_pred` then proves possession in zero knowledge without
// revealing who holds it. None of that was true when this module was written, and the
// comment that used to be here — "nothing anywhere checks it" — is no longer accurate.
//
// ============================================================================
// BUT THE LABEL IN THIS MODULE IS STILL NOT THE PROOF.
// ============================================================================
//
// What rides beside a post today is a STRING, chosen by the sender. The sending client
// now refuses to attach a label the member's own object does not contain
// (`getSelectedBadgeIfHeld`), so an honest client cannot over-claim by accident — which
// is what the bug this comment was expanded for actually was. That is a client-side
// check, and a client-side check is a UX guarantee, not a security one: a modified
// client can still put any label on the wire, because the RECIPIENT verifies nothing.
//
// Closing that gap means attaching the `badge_pred` proof to the post and checking it on
// receipt — `emitBadgeProof` / `verifyBadgeProof` exist in the addon for exactly this and
// are not yet wired into the send/receive path. Until they are, every surface that shows
// a badge must keep saying the claim is unverified, because for a system whose entire
// value proposition is "you can verify this without trusting anyone", quietly letting a
// label pass for a credential would be the worst possible trade.
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
