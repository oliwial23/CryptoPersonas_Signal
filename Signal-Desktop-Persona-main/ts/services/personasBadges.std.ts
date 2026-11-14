// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Badge labels shared by the composer and the legacy badge chip. Keep them in
// sync with the badges in personas-core/src/circuits.rs.
export const BADGE_LABELS = ['Faculty', 'Student', 'Industry'] as const;

export type PersonaBadge = (typeof BADGE_LABELS)[number];

export function isPersonaBadge(value: unknown): value is PersonaBadge {
  return (
    typeof value === 'string' &&
    (BADGE_LABELS as ReadonlyArray<string>).includes(value)
  );
}

// The older post format stored an unverified badge label in message history.
export const BADGE_DISCLAIMER =
  'Unverified badge label from an earlier version.';

// Short form, for places with no room for the full sentence (a chip tooltip).
export const BADGE_DISCLAIMER_SHORT = 'Unverified — not enforced';
