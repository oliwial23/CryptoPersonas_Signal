// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The badge chip shown next to a persona's name on a post.
//
// Deliberately styled to look PROVISIONAL rather than authoritative: dashed border,
// muted colour, a "?" glyph rather than a check or a shield. Signal's real badges and
// verification marks are solid and confident, and a viewer reads that vocabulary
// without thinking about it — so a fake credential must not borrow it.
//
// The claim is unverified (see personasBadges.std.ts): it rides as display metadata
// beside the record, nothing checks it, and any client can send any label. The chip
// carries the disclaimer in its `title`, and the surfaces that offer badges state it in
// full. If this ever becomes a real ZK credential, THIS is the component to make solid —
// and the disclaimer should be deleted in the same commit that makes it true.

import type { JSX } from 'react';

import {
  BADGE_DISCLAIMER,
  BADGE_DISCLAIMER_SHORT,
} from '../../services/personasBadges.std.ts';
import { tw } from '../../axo/tw.dom.tsx';

export function PersonaBadgeChip({
  badge,
}: Readonly<{ badge: string }>): JSX.Element | null {
  if (!badge) {
    return null;
  }

  return (
    <span
      className={tw(
        'ms-1 inline-flex items-center gap-0.5 rounded-full',
        'border border-dashed border-border-secondary',
        'px-1.5 py-px align-middle',
        'type-caption text-label-secondary'
      )}
      // Native tooltip: the chip is small and appears inline in a message header, where
      // there is no room for the full sentence but every viewer should still be one
      // hover away from it.
      title={BADGE_DISCLAIMER}
      aria-label={`${badge} — ${BADGE_DISCLAIMER_SHORT}`}
    >
      {/* No glyph. A literal "?" next to the label read as a rendering fault rather
          than as a deliberate mark of doubt — "? Faculty" looks like a missing icon,
          not like a caveat. The dashed border does that job quietly, and the tooltip
          and aria-label carry the actual disclaimer. */}
      {badge}
    </span>
  );
}
