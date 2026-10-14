// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The bubble for a PROVED badge: "Anonymous proved they hold a Faculty badge."
//
// Solid border and a check glyph, matching PersonaAuthorshipMessage and deliberately
// unlike PersonaBadgeChip's dashed, muted treatment. That visual split carries real
// information and is not decoration: the chip is a string the sender typed and nobody
// checked, this is a Groth16 proof verified before the message was rendered. If the two
// looked alike, the chip would borrow credibility it has not got.
//
// WHERE THE NAME COMES FROM, which is the security property: `badge` is the verifier's
// output (`Engine::verify_badge_proof` maps the proof's public input back through the
// same constant table the prover used), never a name carried in the body. The wire holds
// only the proof. Without that ordering, someone holding a valid Industry proof could
// render it as Faculty and the checkmark would be true while the statement was false.
//
// There is no "unverified" variant, because a badge proof that does not verify is
// dropped at the receive path rather than rendered with a caveat. An unverifiable proof
// has no legitimate sender, so displaying it would only give a forger somewhere to write.

import type { JSX } from 'react';

import { AxoSymbol } from '../../axo/AxoSymbol.dom.tsx';
import { tw } from '../../axo/tw.dom.tsx';

export function PersonaBadgeProofMessage({
  badge,
}: Readonly<{ badge: string }>): JSX.Element {
  return (
    <div
      className={tw(
        'flex flex-col gap-1 rounded-lg border border-border-primary px-3 py-2'
      )}
    >
      <div
        className={tw(
          'flex items-center gap-1.5 type-body-medium text-label-primary'
        )}
      >
        <AxoSymbol.InlineGlyph symbol="check-circle" label={null} />
        {`Proved ${badge} badge`}
      </div>
      <div className={tw('type-body-small text-label-primary')}>
        {`A member of this group proved in zero knowledge that they hold a ${badge} badge.`}
      </div>
      <div className={tw('type-caption text-label-secondary')}>
        {'Verified against badge_pred before this message was shown. The proof does ' +
          'not reveal which member, and an admin had to approve the badge for it to ' +
          'exist at all.'}
      </div>
    </div>
  );
}
