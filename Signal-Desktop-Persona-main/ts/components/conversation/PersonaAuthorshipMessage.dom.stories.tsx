// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import type { JSX } from 'react';

import type { Meta } from '@storybook/react';
import type { ComponentProps } from 'react';
import { PersonaAuthorshipMessage } from './PersonaAuthorshipMessage.dom.tsx';

export default {
  title: 'Components/conversation/PersonaAuthorshipMessage',
} satisfies Meta<ComponentProps<typeof PersonaAuthorshipMessage>>;

export function Default(): JSX.Element {
  return (
    <PersonaAuthorshipMessage first="~quiet-otter" second="~amber-falcon" />
  );
}
