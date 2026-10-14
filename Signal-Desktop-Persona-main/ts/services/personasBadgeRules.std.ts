// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Which badges a member may hold together, mirrored from the circuit.
//
// A `.std` module so the composer (a `.dom` component), the request dialog and the
// admin approval list all apply ONE rule. The rule itself is not ours to invent — it is
// enforced in `personas-core/src/circuits.rs`:
//
//   let assign_badge1 = &is_badge1 & !&student_badge_exists;   // Faculty iff no Student
//   let assign_badge2 = &is_badge2 & !&faculty_badge_exists;   // Student iff no Faculty
//   u.data.badge3 = select(&is_badge3, &industry_c, ...);      // Industry: unconditional
//
// WHY THE UI MUST ENFORCE IT TOO, rather than letting the circuit decide: the circuit
// does not reject a conflicting assignment, it SILENTLY DECLINES it. An admin could
// approve Faculty for someone already holding Student, the callback would be invoked at
// the barrier, the requester would scan, and nothing would happen — no badge, no error,
// nowhere to look. Blocking it at request and approval time is the only way the user
// finds out before wasting a round trip.
//
// So this file is a mirror, and if the circuit's rule ever changes, this must change in
// the same commit.

/** The three badges the circuit knows. Slots are 1-based, matching `badge_pred`. */
export const BADGE_CATALOGUE: ReadonlyArray<{
  slot: number;
  name: string;
  description: string;
}> = [
  { slot: 1, name: 'Faculty', description: 'Cannot be held with Student' },
  { slot: 2, name: 'Student', description: 'Cannot be held with Faculty' },
  { slot: 3, name: 'Industry', description: 'Can be held with either' },
];

/** Badges that cannot be held at the same time, by name. */
const EXCLUSIVE_PAIRS: ReadonlyArray<readonly [string, string]> = [
  ['Faculty', 'Student'],
];

export function badgeNameForSlot(slot: number): string {
  return BADGE_CATALOGUE.find(b => b.slot === slot)?.name ?? `slot ${slot}`;
}

export function badgeSlotForName(name: string): number | undefined {
  return BADGE_CATALOGUE.find(b => b.name === name)?.slot;
}

/**
 * Why `candidate` cannot be granted to someone already holding `held`, or undefined if
 * it can.
 *
 * Returns a SENTENCE rather than a boolean so every surface explains the refusal the
 * same way instead of each inventing its own wording.
 */
export function badgeBlockedReason(
  candidate: string,
  held: ReadonlyArray<string>
): string | undefined {
  if (held.includes(candidate)) {
    return `You already hold ${candidate}.`;
  }
  for (const [a, b] of EXCLUSIVE_PAIRS) {
    const other = candidate === a ? b : candidate === b ? a : undefined;
    if (other != null && held.includes(other)) {
      // Phrased as the circuit behaves: approving it would be accepted and then do
      // nothing, which is worse than a refusal.
      return `${candidate} cannot be held with ${other}, which you already have. An approval would be recorded and then silently have no effect.`;
    }
  }
  return undefined;
}

/**
 * The badge slot out of a replica log body.
 *
 * The replica writes two shapes (`replica/mod.rs`):
 *
 *   "requested badge slot 2"
 *   "approved badge slot 2 for 9f3a1c…"
 *
 * Matched by the `badge slot N` phrase rather than by taking the last word, which is the
 * trap: the APPROVAL body does not end with the slot, so a `rsplit(' ')` reads the
 * target's hex instead and either fails to parse or — worse — happens to parse. Put here,
 * in a `.std` module, so it can be tested; it was originally a private helper in a
 * preload module that pulls in the native addon and therefore could not be.
 */
export function badgeSlotFromLogBody(body: string): number | undefined {
  const match = /badge slot (\d+)/.exec(body);
  if (!match?.[1]) {
    return undefined;
  }
  const slot = Number(match[1]);
  return BADGE_CATALOGUE.some(b => b.slot === slot) ? slot : undefined;
}

/** Badges this member could still usefully request. */
export function requestableBadges(
  held: ReadonlyArray<string>
): ReadonlyArray<{ slot: number; name: string; blockedReason?: string }> {
  return BADGE_CATALOGUE.map(({ slot, name }) => ({
    slot,
    name,
    blockedReason: badgeBlockedReason(name, held),
  }));
}
