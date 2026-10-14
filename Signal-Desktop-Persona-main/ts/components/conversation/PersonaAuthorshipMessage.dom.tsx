// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The bubble for a ZK-PROVED authorship claim: "~alpha and ~beta are the same author."
//
// This used to carry a permanent, inline disclaimer, because the claim was an
// assertion: the sender typed two names and the bubble repeated them. It is now a
// Groth16 proof over `authorship_pred`, verified before the message is rendered, and a
// proof that fails verification is dropped rather than shown. So the warning block is
// GONE — deleted in the change that made it false, not softened. A caveat that has
// stopped being true is worse than none, because it teaches readers to discount the
// ones that still apply.
//
// WHERE THE NAMES COME FROM, which is the whole security property: `first` and `second`
// are derived from the PROOF's own public inputs by `Engine::verify_authorship`, never
// from the message body. The wire carries only the proof. Without that ordering, a
// sender holding a valid proof about two pseudonyms they genuinely own could render it
// beside someone else's persona names and the checkmark would be true while the
// statement was false.
//
// Solid border and a check glyph, deliberately the opposite of PersonaBadgeChip's
// dashed-and-muted treatment: a badge is still an unverified claim, this is not, and
// the two must not look alike.

import type { JSX } from 'react';

import { AUTHORSHIP_VERIFIED_LABEL } from '../../services/personasAuthorship.std.ts';
import { AxoSymbol } from '../../axo/AxoSymbol.dom.tsx';
import { tw } from '../../axo/tw.dom.tsx';

export function PersonaAuthorshipMessage({
  first,
  second,
  verified = false,
}: Readonly<{
  first: string;
  second: string;
  /**
   * False only for a message stored before proofs existed. Verification happens on
   * receipt, so a live proof is either verified or never rendered — but old rows in the
   * database predate that and must not be shown as proved.
   */
  verified?: boolean;
}>): JSX.Element {
  return (
    <div
      className={tw(
        'flex flex-col gap-1 rounded-lg px-3 py-2',
        verified
          ? 'border border-border-primary'
          : 'border border-dashed border-border-secondary'
      )}
    >
      <div
        className={tw(
          'flex items-center gap-1.5 type-body-medium text-label-primary'
        )}
      >
        {verified && (
          <AxoSymbol.InlineGlyph symbol="check-circle" label={null} />
        )}
        {verified ? 'Proved authorship' : 'Claimed authorship (not verified)'}
      </div>
      <div className={tw('type-body-small text-label-primary')}>
        <span className={tw('font-medium')}>{first}</span>
        {' and '}
        <span className={tw('font-medium')}>{second}</span>
        {verified
          ? ' are provably the same author.'
          : ' are claimed to be the same person.'}
      </div>
      <div className={tw('type-caption text-label-secondary')}>
        {verified
          ? AUTHORSHIP_VERIFIED_LABEL
          : 'This message predates proof support, so nothing checked it.'}
      </div>
    </div>
  );
}
