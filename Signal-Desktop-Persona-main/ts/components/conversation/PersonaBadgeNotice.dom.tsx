// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// The bubble for a badge REQUEST or APPROVAL — and, for an admin, the place the badge
// is actually approved.
//
// WHY THE BUTTON LIVES HERE. Approval started out in the status panel, and the flow was
// unusable: an admin saw an unexplained record appear in the chat and had no way to
// connect it to a control three menus away. A request is a social act — one person
// asking another to vouch for them — so the place to answer it is where it was made.
// The panel keeps a list as a backstop for requests that have scrolled off.
//
// Both records are ATTRIBUTABLE by design, so this bubble is shown with its real sender,
// unlike a persona post or a ban poll. That is not a privacy leak to be fixed: you
// cannot ask a named person to vouch for you anonymously, and an approval is meant to be
// an accountable act. The BADGE stays anonymous in use — it lives in the holder's own
// object and `badge_pred` proves possession without revealing who holds it.
//
// WHAT THIS BUBBLE MUST NOT IMPLY. Approving does not grant. It invokes a callback at
// the next settlement barrier, and the badge is written only when the REQUESTER next
// scans. Every string here is written to keep "approved" and "held" distinct, because
// the gap between them is real and a requester who thinks they have a badge they cannot
// yet prove will read the working system as broken.

import type { JSX } from 'react';
import { useState } from 'react';

import { AxoButton } from '../../axo/AxoButton.dom.tsx';
import { AxoSymbol } from '../../axo/AxoSymbol.dom.tsx';
import { tw } from '../../axo/tw.dom.tsx';

export type PersonaBadgeNoticeForUI = {
  kind: 'request' | 'approve';
  /** The record's envelope hash — what an approval names. */
  eh: string;
  slot: number;
  /** Badge name for the slot, resolved by the selector. */
  name: string;
  /** Still awaiting approval, read live from the replica. */
  pending: boolean;
  /** We hold Signal's group-admin role. A client-side gate; see below. */
  canApprove: boolean;
};

export function PersonaBadgeNotice({
  notice,
  isIncoming,
  onApprove,
  onDismiss,
}: Readonly<{
  notice: PersonaBadgeNoticeForUI;
  /** False on our own request — "You requested" rather than an Approve button. */
  isIncoming: boolean;
  onApprove?: (requestEh: string, slot: number) => unknown;
  /** Hide this request LOCALLY. Not a protocol deny — see the buttons below. */
  onDismiss?: (requestEh: string) => unknown;
}>): JSX.Element {
  // Whether this admin has already pressed something. Local, so it survives only as
  // long as the bubble is mounted — which is all it needs to do: the authoritative
  // check is `isBadgeRequestPending` in the service, and this exists purely so the
  // control stops inviting a second press before the replica catches up.
  const [acted, setActed] = useState(false);
  if (notice.kind === 'approve') {
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
          {`${notice.name} badge approved`}
        </div>
        <div className={tw('type-caption text-label-secondary')}>
          {'The requester receives it once they scan — Persona status › ' +
            'Scan now. Until then they cannot post under it.'}
        </div>
      </div>
    );
  }

  // A request. Three distinct states, and conflating any two of them is what made this
  // flow confusing: awaiting someone else's approval, awaiting MINE, or already handled.
  const showApprove = notice.pending && notice.canApprove && isIncoming;

  return (
    <div
      className={tw(
        'flex flex-col gap-2 rounded-lg px-3 py-2',
        notice.pending
          ? 'border border-dashed border-border-secondary'
          : 'border border-border-primary'
      )}
    >
      <div className={tw('type-body-medium text-label-primary')}>
        {isIncoming
          ? `Requested the ${notice.name} badge`
          : `You requested the ${notice.name} badge`}
      </div>

      {!notice.pending && (
        <div className={tw('type-caption text-label-secondary')}>
          {isIncoming
            ? 'Already approved.'
            : 'Approved — press Scan now in Persona status to collect it.'}
        </div>
      )}

      {notice.pending && !notice.canApprove && (
        <div className={tw('type-caption text-label-secondary')}>
          {isIncoming
            ? 'Waiting for a group admin to approve it.'
            : 'Waiting for a group admin. You cannot post under this badge yet.'}
        </div>
      )}

      {showApprove && onApprove != null && (
        <>
          {/* TWO buttons, side by side, from the design system.
              A single button — even a styled one — still read as a line of text inside
              the bubble. A PAIR reads as a decision: two things of equal weight next to
              each other is a shape people recognise as "choose one", which no amount of
              styling on a lone element achieves.
              `strong-affirmative` / `subtle-secondary` rather than hand-rolled classes,
              so the colours come from the theme and survive dark mode. */}
          <div className={tw('flex gap-2')}>
            <AxoButton.Root
              variant="strong-affirmative"
              size="md"
              width="grow"
              symbol="check-circle"
              // Latched the moment it is pressed. `notice.pending` is recomputed on
              // render, which is too late to stop a fast double-click; the service
              // refuses a duplicate too, but a button that visibly stops responding is
              // the part the admin can actually see.
              disabled={acted}
              onClick={() => {
                setActed(true);
                onApprove(notice.eh, notice.slot);
              }}
            >
              Approve
            </AxoButton.Root>
            {onDismiss != null && (
              <AxoButton.Root
                variant="subtle-secondary"
                size="md"
                width="grow"
                symbol="x-circle"
                disabled={acted}
                onClick={() => {
                  setActed(true);
                  onDismiss(notice.eh);
                }}
              >
                Dismiss
              </AxoButton.Root>
            )}
          </div>
          {/* "Dismiss", not "Deny", and the difference is stated rather than implied.
              There is no deny record in the protocol: dismissing hides the request on
              this admin's screen and broadcasts nothing. Labelling it "Deny" would
              promise the requester a refusal that is never sent. */}
          {onDismiss != null && (
            <div className={tw('type-caption text-label-secondary')}>
              {'Dismiss only hides this on your screen — it stays pending for ' +
                'other admins, and the requester is not told.'}
            </div>
          )}
          <div className={tw('type-caption text-label-secondary')}>
            {/*
              Said plainly because an admin acting on this cannot verify it themselves.
              The requester's badges are in their own zk object, unreadable by anyone
              else — that is the privacy property working. The circuit silently DECLINES
              a conflicting grant rather than rejecting it, so a bad approval is a no-op
              with nothing in any log, and the only honest UI is to warn before the click.
            */}
            {'Faculty and Student are mutually exclusive. If they already hold the ' +
              'other one, this approval is recorded and the circuit declines it — ' +
              'their badges are private, so neither of you can tell from here.'}
          </div>
        </>
      )}
    </div>
  );
}
