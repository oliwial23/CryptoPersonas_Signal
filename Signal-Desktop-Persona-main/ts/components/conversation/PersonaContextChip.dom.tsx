// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The CONTEXT CHIP: the name of the context a post was made under, shown beside the
// persona's name on EVERY message in that context.
//
// Why per-message and not once per run: a reader scrolling a mixed timeline needs to
// know which conversation any given message belongs to at the moment they read it.
// Labelling only the first message of a run means the answer is off-screen for every
// message after it, which is exactly the case that matters in a busy group.
//
// This REPLACED an earlier "chain bar" that drew an accent strip across the top of each
// bubble. That bar put the name on the first message of a run and a bare 6px grey spine
// on the rest, and the spine read as a rendering fault rather than as a thread. The chip
// is both more readable and more informative, so the bar was removed rather than
// restyled.
//
// DISTINCT FROM THE BADGE CHIP, deliberately. Both sit in the message header and both
// are unverified, so they must not be mistakable for each other:
//
//                  badge chip                 context chip
//   shape          fully rounded pill         square-ish (rounded-sm)
//   border         dashed                     solid, leading accent bar
//   prefix         none                       "#", the universal channel/topic mark
//
// The "#" does most of the work: it reads as a topic name rather than a credential, so
// "#Hiring" and a dashed "Faculty" pill are not confusable even at a glance or in a
// greyscale screenshot.
//
// TRUST: the context NUMBER is a public input to the post's predicate, and for a
// rate-limited persona the rate limit binds to it in-circuit. The human-readable NAME
// shown here is display metadata carried alongside the record (personasCarriage
// encodePostBody) and is NOT verified — a peer could mislabel its own post's context,
// and for an anonymous or unlimited-pseudonym post nothing in the proof ties the
// message to any context at all. The tooltip says so; the chip stays visually quiet so
// it cannot be read as a protocol guarantee.

import type { JSX } from 'react';

import { tw } from '../../axo/tw.dom.tsx';

export const CONTEXT_CHIP_DISCLAIMER =
  'Context label. The context number is bound inside the proof for a rate-limited ' +
  'persona; this name travels with the message as display metadata and is not ' +
  'verified, so it is not proof that the post belongs to this context.';

export function PersonaContextChip({
  contextName,
}: Readonly<{ contextName: string }>): JSX.Element | null {
  if (!contextName) {
    return null;
  }

  return (
    <span
      className={tw(
        'ms-1 inline-flex items-center rounded-sm',
        // Solid border + a leading accent edge: the same visual language as the chain
        // bar, so chip and chain read as the same concept.
        'border border-border-secondary border-s-2 border-s-label-secondary',
        'px-1 py-px align-middle',
        'type-caption text-label-secondary'
      )}
      title={`Context: “${contextName}”. ${CONTEXT_CHIP_DISCLAIMER}`}
      aria-label={`In context ${contextName}. ${CONTEXT_CHIP_DISCLAIMER}`}
    >
      {/* Rendered as text rather than an icon so it survives greyscale printing and
          needs no icon font. aria-hidden because the label already says "In context". */}
      <span aria-hidden="true" className={tw('me-0.5 opacity-70')}>
        #
      </span>
      {contextName}
    </span>
  );
}
