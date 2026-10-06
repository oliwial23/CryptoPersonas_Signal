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
  stateLost: boolean;
};

export type PersonaStatusDialogProps = {
  status: PersonaStatusForUI | undefined;
  i18n: LocalizerType;
  onClose: () => void;
  /** Emit a scan immediately. See the note on the footer action. */
  onScanNow: () => void;
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
                    ? 'Moves when others 👍/👎 your persona posts. This is your own score — a member\u2019s reputation lives in their own user object, so nobody can look up anyone else\u2019s.'
                    : 'Unavailable — this instance has no member yet, or the native addon predates getReputation().'
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
