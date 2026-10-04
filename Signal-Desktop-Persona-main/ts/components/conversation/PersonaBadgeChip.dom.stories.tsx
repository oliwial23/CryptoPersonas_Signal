// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import type { JSX } from 'react';

import type { Meta } from '@storybook/react';
import type { ComponentProps } from 'react';
import { PersonaBadgeChip } from './PersonaBadgeChip.dom.tsx';

export default {
  title: 'Components/conversation/PersonaBadgeChip',
} satisfies Meta<ComponentProps<typeof PersonaBadgeChip>>;

export function Faculty(): JSX.Element {
  return <PersonaBadgeChip badge="Faculty" />;
}

export function Student(): JSX.Element {
  return <PersonaBadgeChip badge="Student" />;
}

export function Industry(): JSX.Element {
  return <PersonaBadgeChip badge="Industry" />;
}

export function NoBadge(): JSX.Element | null {
  return <PersonaBadgeChip badge="" />;
}
