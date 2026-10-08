// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The CONTEXT THREAD BAR: a quote-shaped strip at the top of a persona message bubble
// naming the context the message belongs to.
//
// Why it looks like a reply rather than like a tag: several personas post into one
// context, and what a reader needs is "these messages belong together". Signal already
// has a visual language for exactly that — the quote block: an accent bar down the
// leading edge with a label beside it. Borrowing it means a context chain reads as a
// thread without anyone having to learn a new convention, which is the whole point of
// the request.
//
// It is NOT a Signal quote, and deliberately not built out of one. A real quote points
// at one specific earlier message and carries that message's author and text. A context
// is a grouping with no parent: there is no single message being replied to, and every
// post in the context is a peer. Rendering it through Quote would require inventing a
// parent message, and Signal's quote keys on (author, timestamp) — where every persona
// post shares the phantom author, so the key would collide across contexts.
//
// Positioned in the bubble where a quote would be, so the layout rhythm matches.
//
// TRUST: the context NUMBER is a public input to the post's predicate and the rate limit
// binds to it in-circuit, for a rate-limited persona. The human-readable NAME shown here
// is display metadata carried alongside the record (see personasCarriage encodePostBody)
// and is not verified — and for an anonymous or unlimited-pseudonym post, the context is
// a label only, with nothing in the proof tying the message to it. The tooltip says so.

import type { JSX } from 'react';

export function PersonaContextBar({
  contextName,
  direction,
}: Readonly<{
  contextName: string;
  direction: 'incoming' | 'outgoing';
}>): JSX.Element | null {
  if (!contextName) {
    return null;
  }

  // Outgoing bubbles are accent-coloured, so a mid-grey strip disappears into them;
  // incoming bubbles are light. Pick contrasts that survive both, and in both themes.
  const isOutgoing = direction === 'outgoing';
  const barColor = isOutgoing
    ? 'rgba(255, 255, 255, 0.65)'
    : 'var(--color-label-secondary)';
  const textColor = isOutgoing
    ? 'rgba(255, 255, 255, 0.85)'
    : 'var(--color-label-secondary)';
  const bgColor = isOutgoing
    ? 'rgba(255, 255, 255, 0.12)'
    : 'rgba(0, 0, 0, 0.05)';

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'stretch',
        gap: 6,
        marginBottom: 4,
        borderRadius: 4,
        backgroundColor: bgColor,
        overflow: 'hidden',
      }}
      title={
        `Context: “${contextName}”. Messages sharing a context form a ` +
        'thread. The context number is bound inside the proof for a rate-limited ' +
        'persona; this name is a label carried with the message and is not verified.'
      }
    >
      {/* The accent bar — the part that makes this read as a reply. */}
      <div
        aria-hidden="true"
        style={{ width: 3, flexShrink: 0, backgroundColor: barColor }}
      />
      <div
        style={{
          padding: '3px 6px 3px 0',
          fontSize: 11,
          fontWeight: 600,
          color: textColor,
          minWidth: 0,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}
      >
        {contextName}
      </div>
    </div>
  );
}
