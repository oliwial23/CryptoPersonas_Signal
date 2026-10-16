// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — the STATUS PANEL, for the person demoing it.
//
// Short rows with what someone using the app needs: can I post anonymously yet, am I
// in, my reputation and badges, am I banned, and anything an admin has to act on. A
// row explains itself only when something is wrong. Developer diagnostics (barrier,
// replica fingerprint) are one small line at the bottom, for bug reports.

import { type JSX } from 'react';

import { AxoButton } from '../axo/AxoButton.dom.tsx';
import { AxoDialog } from '../axo/AxoDialog.dom.tsx';
import { PERSONA_TIPS } from '../services/personasLimitations.std.ts';
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
  pendingBadgeRequests: ReadonlyArray<{
    eh: string;
    slot: number;
    name: string;
  }>;
  scanStuck: boolean;
  outstandingCallbacks: number;
  stateLost: boolean;
  resetState?: 'none' | 'requested' | 'approved';
  catchUp?: 'done' | 'needed' | 'requested';
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
  const caughtUp = (status?.catchUp ?? 'done') === 'done';
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
              Personas are not enabled in this app.
            </div>
          ) : (
            <div className={tw('divide-border-primary divide-y')}>
              {status.banned === true && (
                <Notice title="You are banned in this group">
                  A group admin banned you. You can still send normal messages
                  here, but not anonymous or persona ones.
                </Notice>
              )}
              {status.scanStuck && (
                <Notice title="A scan is unfinished">
                  Press Scan now until this goes away; persona posting waits
                  until it does.
                </Notice>
              )}
              {status.stateLost && (
                <Notice title="Your persona state was lost">
                  Your persona posts will not get through. Use Request a reset
                  below.
                </Notice>
              )}
              <Row
                label="Anonymous sending"
                ok={status.sealedSenderReady}
                value={status.sealedSenderReady ? 'Ready' : 'Not ready yet'}
                detail={
                  status.sealedSenderReady
                    ? undefined
                    : `Waiting to hear from ${status.sealedSenderMissing.join(', ') || 'other members'}.`
                }
              />
              <Row
                label="Group state"
                ok={caughtUp}
                value={caughtUp ? 'Up to date' : 'Waiting for an admin'}
                detail={
                  caughtUp
                    ? undefined
                    : 'An admin\u2019s app sends it automatically while it is open.'
                }
              />
              <Row
                label="Membership"
                ok={status.joined}
                value={status.joined ? 'Joined' : 'Not joined yet'}
                detail={
                  status.joined
                    ? undefined
                    : 'Happens automatically on your first persona action.'
                }
              />
              <Row
                label="Reputation"
                value={
                  status.reputation != null
                    ? String(status.reputation)
                    : '\u2014'
                }
                detail="Changes when others rate your persona posts, after your next scan."
              />
              <Row
                label="Badges"
                value={
                  status.heldBadges.length > 0
                    ? status.heldBadges.join(', ')
                    : 'None'
                }
              />
              <Row
                label="Contexts"
                value={
                  status.topics.length > 0
                    ? status.topics.map(topic => topic.name).join(', ')
                    : 'None'
                }
                detail="Each context allows up to 3 rate-limited personas."
              />
              {status.isSignalAdmin &&
                status.pendingBadgeRequests.length > 0 && (
                  <Section title="Badge requests">
                    <ul className={tw('flex flex-col gap-2')}>
                      {status.pendingBadgeRequests.map(request => (
                        <li
                          key={request.eh}
                          className={tw(
                            'flex items-center justify-between gap-3'
                          )}
                        >
                          <span className={tw('type-body-small')}>
                            {`Anonymous member \u00b7 ${request.name}`}
                          </span>
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
                  </Section>
                )}
              {status.isSignalAdmin &&
                (status.resetRequests?.length ?? 0) > 0 && (
                  <Section title="Reset requests">
                    <ul className={tw('flex flex-col gap-2')}>
                      {status.resetRequests?.map(request => (
                        <li
                          key={request.account}
                          className={tw(
                            'flex items-center justify-between gap-3'
                          )}
                        >
                          <span className={tw('type-body-small')}>
                            {request.name}
                            <span className={tw('text-secondary')}>
                              {request.proofOk
                                ? ' \u00b7 proved not banned'
                                : ' \u00b7 not proved yet'}
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
                  </Section>
                )}
              {status.polls.length > 0 && (
                <Section title="Open polls">
                  {status.polls.map(line => (
                    <div key={line} className={tw('type-body-small')}>
                      {line}
                    </div>
                  ))}
                </Section>
              )}
              {onRequestReset != null && (
                <Section title="Start over">
                  <div className={tw('type-body-small text-secondary')}>
                    {RESET_STATE_TEXT[status.resetState ?? 'none'] ??
                      'If your persona posts stop getting through, ask an admin to let ' +
                        'you rejoin as a new member. You lose your reputation, badges ' +
                        'and personas.'}
                  </div>
                  {(status.resetState ?? 'none') === 'none' && (
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
                  )}
                </Section>
              )}
              <Section title="Good to know">
                <ul className={tw('flex list-disc flex-col gap-1 ps-4')}>
                  {PERSONA_TIPS.map(tip => (
                    <li
                      key={tip}
                      className={tw('type-body-small text-secondary')}
                    >
                      {tip}
                    </li>
                  ))}
                </ul>
              </Section>
              {(status.barrier != null || status.fingerprint) && (
                <div className={tw('pt-2 type-caption text-secondary')}>
                  {`Diagnostics: barrier ${status.barrier ?? '\u2014'} \u00b7 state ${
                    status.fingerprint?.slice(0, 8) ?? '\u2014'
                  }`}
                </div>
              )}
            </div>
          )}
        </AxoDialog.Body>
        <AxoDialog.Footer>
          <AxoDialog.Actions>
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

function Notice({
  title,
  children,
}: {
  title: string;
  children: string;
}): JSX.Element {
  return (
    <div
      className={tw('bg-fill-secondary mb-2 rounded-lg p-3 type-body-medium')}
    >
      <div className={tw('mb-1 flex items-center gap-1.5 font-semibold')}>
        <AxoSymbol.InlineGlyph symbol="x-circle" label={null} />
        {title}
      </div>
      {children}
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <div className={tw('py-2')}>
      <div className={tw('mb-1 type-body-medium font-semibold')}>{title}</div>
      {children}
    </div>
  );
}
