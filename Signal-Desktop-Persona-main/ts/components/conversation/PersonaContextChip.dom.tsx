// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The context chip shown beside a persona's name on a rate-limited post.
//
// It does two jobs at once, and the second is the one the advisors actually asked for:
//
//   1. says WHICH context the post belongs to, so a reader can follow a conversation
//      that spans several contexts in one group;
//   2. distinguishes the two PERSONA KINDS without a legend. A context chip means a
//      rate-limited persona (at most MAX_PSEUDO per context, so the identity is scarce
//      and its reputation means something). No chip means an unlimited pseudonym or an
//      anonymous post, where the identity cost nothing.
//
// Styled as a solid chip, unlike the dashed "unverified" badge chip, because this one IS
// backed by the proof: the context NUMBER is a public input to the post's predicate and
// the rate limit binds to it in-circuit. Only the human-readable NAME is unverified
// display metadata, which is why the tooltip says so rather than the chip looking
// provisional.

import type { JSX } from 'react';

export function PersonaContextChip({
  contextName,
}: Readonly<{ contextName: string }>): JSX.Element | null {
  if (!contextName) {
    return null;
  }

  return (
    <span
      style={{
        marginInlineStart: 4,
        display: 'inline-flex',
        alignItems: 'center',
        borderRadius: 4,
        padding: '0 5px',
        fontSize: 11,
        fontWeight: 500,
        verticalAlign: 'middle',
        backgroundColor: 'var(--color-fill-secondary)',
        color: 'var(--color-label-secondary)',
      }}
      title={
        `Rate-limited persona in the “${contextName}” context. The context ` +
        'number is bound inside the proof; this name is a label carried alongside it ' +
        'and is not verified.'
      }
    >
      {contextName}
    </span>
  );
}
