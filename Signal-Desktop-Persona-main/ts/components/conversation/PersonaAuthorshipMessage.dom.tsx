// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The bubble for an UNVERIFIED authorship claim: "~alpha and ~beta are the same person."
//
// The design problem here is the opposite of most UI work. A claim like this is
// PERSUASIVE — it tells the reader that two anonymous voices are one person, which is
// exactly the kind of statement that changes how a conversation is read. If it renders
// like a fact, the reader will treat it as one. So the disclaimer is not a tooltip
// tucked away like the badge chip's: it is inline, always visible, and cannot be
// dismissed, because a reader who sees the claim must also see that nothing verified it.
//
// When `Member::authorship()` and its binding land (PERSONAS_SERVERLESS_TODO.md section
// 1), this becomes a real proof and the warning block below should be deleted in the
// same commit — not softened, deleted, because at that point it would be false.

import type { JSX } from 'react';

import { AUTHORSHIP_DISCLAIMER } from '../../services/personasAuthorship.std.ts';
import { tw } from '../../axo/tw.dom.tsx';

export function PersonaAuthorshipMessage({
  first,
  second,
}: Readonly<{ first: string; second: string }>): JSX.Element {
  return (
    <div
      className={tw(
        'flex flex-col gap-1 rounded-lg',
        'border border-dashed border-border-secondary',
        'px-3 py-2'
      )}
    >
      <div className={tw('type-body-medium text-label-primary')}>
        Claimed authorship
      </div>
      <div className={tw('type-body-small text-label-primary')}>
        <span className={tw('font-medium')}>{first}</span>
        {' and '}
        <span className={tw('font-medium')}>{second}</span>
        {' are claimed to be the same person.'}
      </div>
      {/* Inline and permanent, not a tooltip. See the note at the top of this file. */}
      <div className={tw('type-caption text-label-secondary')}>
        {AUTHORSHIP_DISCLAIMER}
      </div>
    </div>
  );
}
