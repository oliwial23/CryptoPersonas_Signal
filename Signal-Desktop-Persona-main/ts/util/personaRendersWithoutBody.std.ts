// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Which persona messages render with NO body — and therefore must not be dropped as
// empty.
//
// This list exists because the same bug kept being introduced, once per persona record
// type that renders from its own field instead of from `body`:
//
//   * a ZK poll          -> personaPoll
//   * an authorship proof -> personaAuthorship
//   * a badge request    -> personaBadgeNotice
//   * a badge proof      -> personaBadgeProof
//
// Each time, the receive path was correct, the component was correct, and
// `isMessageEmpty` then discarded the message one step later because it had no body, no
// attachment and no Signal `poll`. The failure is SILENT and asymmetric, which is what
// makes it cost hours: the sender's own copy is built locally and never passes through
// that check, so the person who sent it sees it in their timeline and concludes it was
// delivered. Only the recipients lose it — and for a badge request, the recipient who
// loses it is the admin who was supposed to act on it.
//
// So the rule has one home, enumerated and tested. A new bodiless persona record type is
// added HERE, and the test below fails until it is.

import type { MessageAttributesType } from '../model-types.d.ts';

/**
 * The attribute names that each, alone, give a persona message something to display.
 *
 * Exported so a test can assert the list is complete rather than trusting a reviewer to
 * notice a missing `||`.
 */
export const PERSONA_BODILESS_FIELDS = [
  'personaPoll',
  'personaAuthorship',
  'personaBadgeNotice',
  'personaBadgeProof',
] as const satisfies ReadonlyArray<keyof MessageAttributesType>;

/** Does this message render from a persona field rather than from `body`? */
export function personaRendersWithoutBody(
  attributes: Pick<MessageAttributesType, (typeof PERSONA_BODILESS_FIELDS)[number]>
): boolean {
  return PERSONA_BODILESS_FIELDS.some(field => attributes[field] != null);
}
