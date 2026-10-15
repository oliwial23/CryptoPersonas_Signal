// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — the STATUS PANEL.
//
// Everything shown here was previously reachable only by typing
// `window.SignalDebug.personas*` into devtools, which meant that in practice only the
// person who wrote the code could tell whether the demo was actually working.
//
// The panel is deliberately willing to look bad. Four of these values are the
// difference between "working" and "appears to be working":
//
//   Sealed sender  — false means a persona post is NOT protected.
//   Joined         — false means persona actions are refused.
//   Barrier        — not advancing means no ban can ever settle.
//   Fingerprint    — differs across instances means the replicas have diverged, and
//                    every tally, flag and ban is unreliable on at least one of them.
//
// So each row states the consequence, not just the value. A status display that only
// ever shows green is worth nothing.

import { type JSX } from 'react';

import { AxoButton } from '../axo/AxoButton.dom.tsx';
import { AxoDialog } from '../axo/AxoDialog.dom.tsx';
import { KNOWN_LIMITATIONS } from '../services/personasLimitations.std.ts';
import { AxoSymbol } from '../axo/AxoSymbol.dom.tsx';
import { tw } from '../axo/tw.dom.tsx';
import type { LocalizerType } from '../types/Util.std.ts';

export type PersonaStatusForUI = {
  enabled: boolean;
  joined: boolean;
  sealedSenderReady: boolean;
  sealedSenderMissing: ReadonlyArray<string>;
  barrier?: number;
  fingerprint?: string;
  topics: ReadonlyArray<{ name: string; context: number }>;
  polls: ReadonlyArray<string>;
  recordCount: number;
  reputation?: number;
  isSignalAdmin: boolean;
  autoScan: boolean;
  banned?: boolean;
  authorshipZk: boolean;
  heldBadges: ReadonlyArray<string>;
  pendingBadgeRequests: ReadonlyArray<{ eh: string; slot: number; name: string }>;
  scanStuck: boolean;
  outstandingCallbacks: number;
  stateLost: boolean;
  resetState?: 'none' | 'requested' | 'approved';
  resetRequests?: ReadonlyArray<{
    account: string;
    name: string;
    proofOk: boolean;
    reason?: string;
  }>;
};

const RESET_STATE_TEXT: Record<string, string | undefined> = {
  requested: 'Reset requested \u2014 waiting for a group admin to approve it.',
  approved: 'Approved \u2014 re-joining as a new member in a moment.',
};

export type PersonaStatusDialogProps = {
  status: PersonaStatusForUI | undefined;
  i18n: LocalizerType;
  onClose: () => void;
  /** Emit a scan immediately. See the note on the footer action. */
  onScanNow: () => void;
  /** Approve a badge request. Only supplied to a Signal group admin. */
  onApproveBadge?: (requestEh: string, slot: number) => void;
  /** Hide a request from this admin's queue. LOCAL — no record, nothing broadcast. */
  onDismissBadge?: (requestEh: string) => void;
  /** Open (or bring forward) extra member 1 or 2. Only in the installable build. */
  onOpenExtraMember?: (slot: 1 | 2) => void;
  /** Ask the group's admins to let this account join again with a fresh member. */
  onRequestReset?: () => void;
  /** As an admin: allow a member's re-join. */
  onApproveReset?: (account: string) => void;
  /** As an admin: hide a reset request (local only). */
  onDismissReset?: (account: string) => void;
};

function Row({
  label,
  value,
  ok,
  detail,
}: {
  label: string;
  value: string;
  ok?: boolean;
  detail?: string;
}): JSX.Element {
  return (
    <div className={tw('flex flex-col gap-0.5 py-2')}>
      <div className={tw('flex items-center justify-between gap-3')}>
        <span className={tw('type-body-medium text-secondary')}>{label}</span>
        <span className={tw('flex items-center gap-1.5 type-body-medium')}>
          {ok != null && (
            <AxoSymbol.InlineGlyph
              symbol={ok ? 'check-circle' : 'x-circle'}
              label={ok ? 'ok' : 'not ready'}
            />
          )}
          <span className={tw('font-medium')}>{value}</span>
        </span>
      </div>
      {detail != null && (
        <div className={tw('type-body-small text-secondary')}>{detail}</div>
      )}
    </div>
  );
}

export function PersonaStatusDialog({
  status,
  i18n,
  onClose,
  onScanNow,
  onApproveBadge,
  onDismissBadge,
  onOpenExtraMember,
  onRequestReset,
  onApproveReset,
  onDismissReset,
}: PersonaStatusDialogProps): JSX.Element {
  return (
    <AxoDialog.Root open onOpenChange={onClose}>
      <AxoDialog.Content size="md" escape="cancel-is-destructive">
        <AxoDialog.Header>
          <AxoDialog.Title>Persona status</AxoDialog.Title>
          <AxoDialog.Close />
        </AxoDialog.Header>
        <AxoDialog.Body>
          {status == null || !status.enabled ? (
            <div className={tw('type-body-medium text-secondary')}>
              The personas engine is not enabled in this instance. Launch with
              PERSONAS_AUTO_REGISTER or PERSONAS_KEYS_DIR set.
            </div>
          ) : (
            <div className={tw('divide-y divide-border-primary')}>
              {status.stateLost && (
                <div
                  className={tw(
                    'mb-2 rounded-lg bg-fill-secondary p-3 type-body-medium'
                  )}
                >
                  <div className={tw('mb-1 flex items-center gap-1.5 font-semibold')}>
                    <AxoSymbol.InlineGlyph symbol="x-circle" label={null} />
                    Protocol state was lost
                  </div>
                  This conversation shows persona messages, but the replica holds no
                  records — so the app was restarted. The bulletin is memory-only and
                  does not survive a restart, while the chat history does. Tallies read
                  as zero and bans cannot settle until the group is re-established.
                </div>
              )}
              {status.banned === true && (
                <div
                  className={tw(
                    'mb-2 rounded-lg bg-fill-secondary p-3 type-body-medium'
                  )}
                >
                  <div className={tw('mb-1 flex items-center gap-1.5 font-semibold')}>
                    <AxoSymbol.InlineGlyph symbol="x-circle" label={null} />
                    You are banned in this group
                  </div>
                  {'A group admin flagged your posts. Anonymous and pseudonymous ' +
                    'posting are disabled HERE — your proofs for them are no longer ' +
                    'satisfiable, so the protocol enforces this, not just the app. You ' +
                    'can still send ordinary messages under your real identity in this ' +
                    'group, and your persona privileges in other groups are unaffected.'}
                </div>
              )}
              {status.scanStuck && (
                <div
                  className={tw(
                    'mb-2 rounded-lg bg-fill-secondary p-3 type-body-medium'
                  )}
                >
                  <div className={tw('mb-1 flex items-center gap-1.5 font-semibold')}>
                    <AxoSymbol.InlineGlyph symbol="x-circle" label={null} />
                    Unfinished scan — posting is blocked
                  </div>
                  {`${status.outstandingCallbacks} callback(s) still outstanding. A partly
                  finished sweep leaves the engine in a state where posting, rating and
                  voting are refused — before this was detected they aborted the whole
                  window instead. Press Scan now until this message clears.`}
                </div>
              )}
              <Row
                label="Sealed sender"
                ok={status.sealedSenderReady}
                value={status.sealedSenderReady ? 'Ready' : 'Not ready'}
                detail={
                  status.sealedSenderReady
                    ? 'Persona posts can be sealed — the sender is hidden.'
                    : `Waiting on a reply from ${status.sealedSenderMissing.join(', ') || 'other members'}. Until then a persona post is NOT protected.`
                }
              />
              <Row
                label="Membership"
                ok={status.joined}
                value={status.joined ? 'Joined' : 'Not joined'}
                detail={
                  status.joined
                    ? undefined
                    : 'Persona actions are refused until this instance joins (happens automatically on first use).'
                }
              />
              <Row
                label="Settlement barrier"
                value={status.barrier != null ? String(status.barrier) : '—'}
                detail={
                  status.barrier == null
                    ? 'Engine unavailable.'
                    : 'Should increase over time. If it is stuck, no ban can settle.'
                }
              />
              <Row
                label="Replica fingerprint"
                value={
                  status.fingerprint ? `${status.fingerprint.slice(0, 16)}…` : '—'
                }
                detail="Must be identical on every instance. If they differ, the replicas have diverged and tallies, flags and bans are unreliable."
              />
              <Row
                label="Your reputation"
                value={
                  status.reputation != null ? String(status.reputation) : '—'
                }
                detail={
                  status.reputation != null
                    ? 'Your own score, and only yours — reputation lives inside your zk user object, so nobody can look up anyone else\u2019s. It moves when a SCAN absorbs a 👍/👎 on one of your persona posts, not when the rating is sent: they rate, then you scan. 0 on a new member is correct, not a failure.'
                    : 'Unavailable — this instance is an observer with no member object. A member with no ratings yet reads 0, not this.'
                }
              />
              <Row
                label="Scanning"
                value={status.autoScan ? 'On send + daily' : 'On send only'}
                detail={
                  'A scan is attempted before every persona message, which is what keeps ' +
                  'you under the 200-interaction limit the post predicate enforces \u2014 ' +
                  'past it, your proofs stop being satisfiable and you cannot post at all. ' +
                  'Most attempts do nothing, because the engine refuses a scan with no ' +
                  'callbacks outstanding.' +
                  (status.autoScan
                    ? ' A 24-hour catch-up also runs, for a client left open without sending.'
                    : ' The 24-hour catch-up is disabled (PERSONAS_AUTO_SCAN=off), so an idle client will not absorb a revocation until it sends something.')
                }
              />
              <Row
                label="Signal group admin"
                value={status.isSignalAdmin ? 'Yes' : 'No'}
                detail={
                  status.isSignalAdmin
                    ? 'You can create contexts and open revocation polls. The poll itself still rides the shared phantom, so nobody learns you opened it \u2014 but if only admins ever open one, an observer who knows the admin set can infer it. A client-side gate, not enforcement.'
                    : 'Creating a context and opening a revocation poll are limited to group admins. A client-side gate, not enforcement \u2014 persona records are ordinary message bodies the server never inspects, so a modified client ignores it.'
                }
              />
              <Row
                label="Badges held (in your object)"
                value={
                  status.heldBadges.length > 0
                    ? status.heldBadges.join(', ')
                    : 'None'
                }
                detail={
                  status.heldBadges.length > 0
                    ? 'Zero-knowledge badges: an approver invoked your request\u2019s callback, and your own scan wrote the badge into your private zk object \u2014 nobody can add one there for you or read it from outside. \u201cProve badge\u201d sends a Groth16 proof over badge_pred that you hold it, without revealing which member you are; recipients verify the proof before showing it. The badge label on an ordinary post is different: it is only attached when you hold the badge, but it is display metadata, not a proof, so a modified client could fake it. Use \u201cProve badge\u201d when it matters.'
                    : 'You hold no zero-knowledge badges yet. Request one; once an admin approves, your next scan (it runs before each persona post, or use \u201cScan now\u201d) writes it into your private zk object, from where \u201cProve badge\u201d can prove it in zero knowledge.'
                }
              />
              <Row
                label="Authorship proofs"
                ok={status.authorshipZk}
                value={status.authorshipZk ? 'Verified in ZK' : 'Unavailable'}
                detail={
                  status.authorshipZk
                    ? 'A claim carries a Groth16 proof over authorship_pred binding both pseudonyms to one secret key. Recipients verify before rendering and DROP a proof that fails, and the names shown are read from the proof\u2019s public inputs rather than from the message \u2014 so a valid proof cannot be shown beside someone else\u2019s persona names. Claims cannot be retracted.'
                    : 'This addon has no emitAuthorship/verifyAuthorship binding, so a claim could only be an unverified assertion. Rebuild the native engine.'
                }
              />
              <Row
                label="Am I banned?"
                ok={status.banned === false}
                value={
                  status.banned == null
                    ? 'Unknown'
                    : status.banned
                      ? 'Yes — personas disabled here'
                      : 'No'
                }
                detail={
                  status.banned == null
                    ? 'Cannot tell: this instance has no member object, or the addon predates the isBanned() binding. Shown as Unknown rather than No, because a wrong "No" here is the reassuring answer that hides the problem.'
                    : status.banned
                      ? 'Set when your own scan absorbed a BAN callback. It is your object that carries it, which is why only you can read it — and why a ban only takes effect once you scan.'
                      : 'No ban has been absorbed by any of your scans. A ban cast moments ago may not have settled yet: it is invoked at the next settlement barrier and lands at your next scan.'
                }
              />
              <Row
                label="Records held"
                value={String(status.recordCount)}
                detail="Joins, posts, polls, ballots and scans this replica has folded in."
              />
              <Row
                label="Contexts"
                value={String(status.topics.length)}
                detail={
                  status.topics.length > 0
                    ? status.topics.map(topic => topic.name).join(', ')
                    : 'None yet — create one to use a rate-limited persona.'
                }
              />
              {status.isSignalAdmin && status.pendingBadgeRequests.length > 0 && (
                <div className={tw('pt-3')}>
                  <div className={tw('mb-1 type-body-medium font-semibold')}>
                    Badge requests awaiting your approval
                  </div>
                  <div className={tw('type-body-small text-label-secondary')}>
                    {'Usually you would approve these from the request in the chat \u2014 ' +
                      'this list is the backstop for one that has scrolled away. ' +
                      'Approving invokes the requester\u2019s callback at the next ' +
                      'settlement barrier; the badge is written into their object when ' +
                      'THEY next scan, not now.'}
                  </div>
                  <ul className={tw('mt-2 flex flex-col gap-2')}>
                    {status.pendingBadgeRequests.map(request => (
                      <li
                        key={request.eh}
                        className={tw('flex items-center justify-between gap-3')}
                      >
                        <span className={tw('type-body-small')}>
                          {request.name}
                          <span className={tw('text-label-secondary')}>
                            {` \u00b7 ${request.eh.slice(0, 12)}\u2026`}
                          </span>
                        </span>
                        {/* Same pair as the in-chat notification, so an admin does
                            not learn two different gestures for one decision. */}
                        <span className={tw('flex shrink-0 gap-2')}>
                          {onApproveBadge != null && (
                            <AxoButton.Root
                              variant="strong-affirmative"
                              size="sm"
                              symbol="check-circle"
                              onClick={() =>
                                onApproveBadge(request.eh, request.slot)
                              }
                            >
                              Approve
                            </AxoButton.Root>
                          )}
                          {onDismissBadge != null && (
                            <AxoButton.Root
                              variant="subtle-secondary"
                              size="sm"
                              symbol="x-circle"
                              onClick={() => onDismissBadge(request.eh)}
                            >
                              Dismiss
                            </AxoButton.Root>
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                  {/*
                    NO exclusivity check on these buttons, and that is not an omission.

                    An earlier version disabled Approve using
                    `badgeBlockedReason(request.name, status.heldBadges)`. That was
                    wrong in the direction that matters: `status.heldBadges` is the
                    ADMIN's own badges. It would have stopped an admin who happens to
                    hold Student from approving anybody's Faculty request, while
                    cheerfully allowing the one grant that actually conflicts.

                    The deeper point is that an admin CANNOT check this. The requester's
                    badges live in their own zk object, which nobody else can read --
                    that is the privacy property working as designed. So exclusivity is
                    enforced where the holder knows their own state: the requester's own
                    menu (`requestableBadges`), and the circuit, which silently declines
                    a conflicting assignment. Hence the note below rather than a
                    disabled button.
                  */}
                  <div className={tw('mt-2 type-caption text-label-secondary')}>
                    {'If the requester already holds a conflicting badge (Faculty and ' +
                      'Student are mutually exclusive), the approval is recorded and ' +
                      'the circuit declines it. You cannot tell from here \u2014 their ' +
                      'badges are private to them.'}
                  </div>
                </div>
              )}
              {status.isSignalAdmin && (status.resetRequests?.length ?? 0) > 0 && (
                <div className={tw('py-2')}>
                  <div className={tw('mb-1 type-body-medium font-semibold')}>
                    Reset requests
                  </div>
                  <div className={tw('type-body-small text-label-secondary')}>
                    {'Approving lets that account join once more as a brand-new member ' +
                      '(its old reputation, badges and personas are abandoned). "Not ' +
                      'banned" means they proved, in zero knowledge and against this ' +
                      'group\u2019s own state, that their member is not banned and ' +
                      'has just finished a scan, so every ban settled so far was ' +
                      'absorbed. A ban decided later on one of their old posts cannot ' +
                      'follow them to the new member.'}
                  </div>
                  <ul className={tw('mt-2 flex flex-col gap-2')}>
                    {status.resetRequests?.map(request => (
                      <li
                        key={request.account}
                        className={tw('flex items-center justify-between gap-3')}
                      >
                        <span className={tw('type-body-small')}>
                          {request.name}
                          <span className={tw('text-label-secondary')}>
                            {request.proofOk
                              ? ' \u00b7 not banned (proved)'
                              : ` \u00b7 NOT proved: ${request.reason ?? 'no proof'}`}
                          </span>
                        </span>
                        <span className={tw('flex shrink-0 gap-2')}>
                          {onApproveReset != null && (
                            <AxoButton.Root
                              variant="strong-affirmative"
                              size="sm"
                              symbol="check-circle"
                              onClick={() => onApproveReset(request.account)}
                            >
                              Approve
                            </AxoButton.Root>
                          )}
                          {onDismissReset != null && (
                            <AxoButton.Root
                              variant="subtle-secondary"
                              size="sm"
                              symbol="x-circle"
                              onClick={() => onDismissReset(request.account)}
                            >
                              Dismiss
                            </AxoButton.Root>
                          )}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {onRequestReset != null && (
                <div className={tw('py-2')}>
                  <div className={tw('mb-1 type-body-medium font-semibold')}>
                    Start over
                  </div>
                  <div className={tw('type-body-small text-label-secondary')}>
                    {RESET_STATE_TEXT[status.resetState ?? 'none'] ??
                      'If your persona member is stuck (posts are not getting ' +
                          'through), ask a group admin to let you join again as a new ' +
                          'member. Each account can join once; an admin\u2019s approval ' +
                          'allows one more. You lose your reputation, badges and ' +
                          'personas. The request names you, and proves you are not ' +
                          'banned.'}
                  </div>
                  {status.resetState === 'none' || status.resetState == null ? (
                    <div className={tw('mt-2')}>
                      <AxoButton.Root
                        variant="subtle-secondary"
                        size="sm"
                        symbol="refresh"
                        onClick={onRequestReset}
                      >
                        Request a reset
                      </AxoButton.Root>
                    </div>
                  ) : null}
                </div>
              )}
              <div className={tw('pt-3')}>
                <div className={tw('mb-1 type-body-medium font-semibold')}>
                  Known limitations
                </div>
                <div className={tw('type-body-small text-secondary')}>
                  Real gaps in this build, not boilerplate — worth knowing before
                  describing what the demo proves.
                </div>
                <ul className={tw('mt-2 flex flex-col gap-2')}>
                  {KNOWN_LIMITATIONS.map(limitation => (
                    <li key={limitation.title}>
                      <div className={tw('type-body-small font-medium')}>
                        {limitation.title}
                      </div>
                      <div className={tw('type-body-small text-secondary')}>
                        {limitation.detail}
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
              {status.polls.length > 0 && (
                <div className={tw('py-2')}>
                  <div className={tw('mb-1 type-body-medium text-secondary')}>
                    Open polls
                  </div>
                  {status.polls.map(line => (
                    <div key={line} className={tw('type-body-small')}>
                      {line}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </AxoDialog.Body>
        <AxoDialog.Footer>
          <AxoDialog.Actions>
            {/* Moved here out of the composer menu: scanning is automatic now, so this
                is a demo affordance rather than something a user needs. Kept because it
                is still the only way to make a settled ban bite on a keystroke in front
                of an audience. */}
            {/* Playing several members from one Mac: the same as File > Open Extra
                Member, here because a menu is easy to miss. */}
            {onOpenExtraMember != null && (
              <>
                <AxoDialog.Action
                  variant="subtle-secondary"
                  onClick={() => onOpenExtraMember(1)}
                >
                  Open extra member 1
                </AxoDialog.Action>
                <AxoDialog.Action
                  variant="subtle-secondary"
                  onClick={() => onOpenExtraMember(2)}
                >
                  Open extra member 2
                </AxoDialog.Action>
              </>
            )}
            <AxoDialog.Action variant="strong-secondary" onClick={onScanNow}>
              Scan now
            </AxoDialog.Action>
            <AxoDialog.Action variant="strong-primary" onClick={onClose}>
              {i18n('icu:ok')}
            </AxoDialog.Action>
          </AxoDialog.Actions>
        </AxoDialog.Footer>
      </AxoDialog.Content>
    </AxoDialog.Root>
  );
}
