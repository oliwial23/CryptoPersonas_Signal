// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — CONTACT CODES, shown in Settings → General and in Persona status.
//
// Testers cannot see each other in the member directory (only the shared demo members
// and their own extra members). To add someone, you type the contact code they gave you;
// to be added, you give yours. See personaRoster.preload.ts.

import { type JSX, useCallback, useEffect, useState } from 'react';

import { AxoButton } from '../axo/AxoButton.dom.tsx';
import { tw } from '../axo/tw.dom.tsx';

export type PersonaContactsPanelProps = {
  /** Our contact code (loaded asynchronously by the caller). */
  loadCode: () => Promise<string | undefined>;
  /** Retire our code for a new one; resolves to the new code. */
  renewCode: () => Promise<string>;
  /** Add the member whose code this is. */
  addByCode: (
    code: string
  ) => Promise<{ ok: true; name: string } | { ok: false; reason: string }>;
};

export function PersonaContactsPanel({
  loadCode,
  renewCode,
  addByCode,
}: PersonaContactsPanelProps): JSX.Element {
  const [code, setCode] = useState<string | undefined>();
  const [copied, setCopied] = useState(false);
  const [confirmingRenew, setConfirmingRenew] = useState(false);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<
    { ok: boolean; text: string } | undefined
  >();

  useEffect(() => {
    let alive = true;
    const load = async () => {
      const value = await loadCode();
      if (alive) {
        setCode(value);
      }
    };
    void load();
    return () => {
      alive = false;
    };
  }, [loadCode]);

  const copy = useCallback(async () => {
    if (!code) {
      return;
    }
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [code]);

  const renew = useCallback(async () => {
    setConfirmingRenew(false);
    setCode(await renewCode());
  }, [renewCode]);

  const add = useCallback(async () => {
    setBusy(true);
    setResult(undefined);
    try {
      const outcome = await addByCode(input);
      setResult(
        outcome.ok
          ? {
              ok: true,
              text: `Added ${outcome.name}. You can now message them or add them to a group.`,
            }
          : { ok: false, text: outcome.reason }
      );
      if (outcome.ok) {
        setInput('');
      }
    } finally {
      setBusy(false);
    }
  }, [addByCode, input]);

  return (
    <div className={tw('flex flex-col gap-4')}>
      <div className={tw('flex flex-col gap-1')}>
        <div className={tw('type-body-medium font-semibold')}>
          Your contact code
        </div>
        <div className={tw('type-body-small text-secondary')}>
          Give this to someone so they can add you. Only people you give it to
          can find you.
        </div>
        <div className={tw('mt-1 flex flex-wrap items-center gap-2')}>
          <span
            className={tw(
              'rounded-md bg-secondary px-3 py-1 font-mono type-title-small'
            )}
          >
            {code ?? '…'}
          </span>
          <AxoButton.Root
            variant="subtle-secondary"
            size="sm"
            symbol="copy"
            disabled={!code}
            onClick={() => void copy()}
          >
            {copied ? 'Copied' : 'Copy'}
          </AxoButton.Root>
          {confirmingRenew ? (
            <>
              <AxoButton.Root
                variant="subtle-destructive"
                size="sm"
                onClick={() => void renew()}
              >
                Replace my code
              </AxoButton.Root>
              <AxoButton.Root
                variant="subtle-secondary"
                size="sm"
                onClick={() => setConfirmingRenew(false)}
              >
                Keep it
              </AxoButton.Root>
            </>
          ) : (
            <AxoButton.Root
              variant="subtle-secondary"
              size="sm"
              symbol="refresh"
              disabled={!code}
              onClick={() => setConfirmingRenew(true)}
            >
              New code
            </AxoButton.Root>
          )}
        </div>
        {confirmingRenew && (
          <div className={tw('type-body-small text-secondary')}>
            Your current code will stop working. People who already added you
            keep you as a contact.
          </div>
        )}
      </div>

      <div className={tw('flex flex-col gap-1')}>
        <div className={tw('type-body-medium font-semibold')}>
          Add a Signal Personas user
        </div>
        <div className={tw('type-body-small text-secondary')}>
          Type the contact code they gave you.
        </div>
        <div className={tw('mt-1 flex items-center gap-2')}>
          <input
            className={tw(
              'w-40 rounded-md border border-primary bg-secondary px-3 py-1 font-mono type-body-medium text-primary'
            )}
            placeholder="K7PQ-2MXD"
            value={input}
            maxLength={12}
            onChange={event => setInput(event.target.value)}
            onKeyDown={event => {
              if (event.key === 'Enter' && input.trim() && !busy) {
                void add();
              }
            }}
            aria-label="Contact code"
          />
          <AxoButton.Root
            variant="strong-primary"
            size="sm"
            disabled={!input.trim() || busy}
            onClick={() => void add()}
          >
            {busy ? 'Adding…' : 'Add'}
          </AxoButton.Root>
        </div>
        {result && (
          <div
            className={tw(
              result.ok
                ? 'type-body-small text-secondary'
                : 'type-body-small text-destructive'
            )}
            role="status"
          >
            {result.text}
          </div>
        )}
      </div>
    </div>
  );
}
