// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import type { JSX } from 'react';

import { action } from '@storybook/addon-actions';
import type { Meta } from '@storybook/react';
import { PersonaStatusDialog } from './PersonaStatusDialog.dom.tsx';
import type { PersonaStatusForUI } from './PersonaStatusDialog.dom.tsx';

const { i18n } = window.SignalContext;

export default {
  title: 'Components/PersonaStatusDialog',
} satisfies Meta<typeof PersonaStatusDialog>;

const onClose = action('onClose');
const onScanNow = action('onScanNow');

const healthyStatus: PersonaStatusForUI = {
  enabled: true,
  joined: true,
  sealedSenderReady: true,
  sealedSenderMissing: [],
  barrier: 42,
  fingerprint: 'a1b2c3d4e5f60718293a4b5c6d7e8f90',
  topics: [
    { name: 'general', context: 1001 },
    { name: 'moderation', context: 1002 },
  ],
  polls: ['Should we meet weekly or biweekly? — 3 votes'],
  recordCount: 128,
  reputation: 7,
  isSignalAdmin: true,
  autoScan: true,
  stateLost: false,
};

export function Healthy(): JSX.Element {
  return (
    <PersonaStatusDialog status={healthyStatus} i18n={i18n} onClose={onClose} onScanNow={onScanNow} />
  );
}

export function NotJoinedYet(): JSX.Element {
  return (
    <PersonaStatusDialog
      status={{
        ...healthyStatus,
        joined: false,
        sealedSenderReady: false,
        sealedSenderMissing: ['~bob', '~carol'],
        barrier: undefined,
        fingerprint: undefined,
        topics: [],
        polls: [],
        recordCount: 0,
        reputation: undefined,
      }}
      i18n={i18n}
      onClose={onClose}
      onScanNow={onScanNow}
    />
  );
}

export function StateLost(): JSX.Element {
  return (
    <PersonaStatusDialog
      status={{ ...healthyStatus, stateLost: true }}
      i18n={i18n}
      onClose={onClose}
      onScanNow={onScanNow}
    />
  );
}

export function Disabled(): JSX.Element {
  return (
    <PersonaStatusDialog
      status={{ ...healthyStatus, enabled: false }}
      i18n={i18n}
      onClose={onClose}
      onScanNow={onScanNow}
    />
  );
}
