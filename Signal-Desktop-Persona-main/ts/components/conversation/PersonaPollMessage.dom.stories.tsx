// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import type { JSX } from 'react';

import { action } from '@storybook/addon-actions';
import type { Meta } from '@storybook/react';
import { PersonaPollMessage } from './PersonaPollMessage.dom.tsx';
import type { PersonaPollForUI } from './PersonaPollMessage.dom.tsx';

export default {
  title: 'Components/conversation/PersonaPollMessage',
} satisfies Meta<typeof PersonaPollMessage>;

const sendPollVote = action('sendPollVote');

const standardPoll: PersonaPollForUI = {
  question: 'Should we meet weekly or biweekly?',
  options: ['Weekly', 'Biweekly', 'No preference'],
  kind: 'standard',
  statusLine: 'Weekly: 3 · Biweekly: 1 · No preference: 0',
};

const banPoll: PersonaPollForUI = {
  question: 'Revoke ~amber-falcon?',
  options: ['Yes, revoke', 'No, keep'],
  kind: 'ban',
  statusLine: 'Yes, revoke: 2 · No, keep: 1',
};

function Bubble({
  children,
  outgoing,
}: {
  children: JSX.Element;
  outgoing?: boolean;
}): JSX.Element {
  return (
    <div
      style={{
        display: 'inline-block',
        borderRadius: 18,
        padding: 12,
        background: outgoing ? '#2c6bed' : '#e4e4e5',
      }}
    >
      {children}
    </div>
  );
}

export function Incoming(): JSX.Element {
  return (
    <Bubble>
      <PersonaPollMessage
        poll={standardPoll}
        direction="incoming"
        messageId="story-message-1"
        sendPollVote={sendPollVote}
      />
    </Bubble>
  );
}

export function Outgoing(): JSX.Element {
  return (
    <Bubble outgoing>
      <PersonaPollMessage
        poll={standardPoll}
        direction="outgoing"
        messageId="story-message-2"
        sendPollVote={sendPollVote}
      />
    </Bubble>
  );
}

export function AlreadyVoted(): JSX.Element {
  return (
    <Bubble>
      <PersonaPollMessage
        poll={{ ...standardPoll, myVote: 0 }}
        direction="incoming"
        messageId="story-message-3"
        sendPollVote={sendPollVote}
      />
    </Bubble>
  );
}

export function BanPoll(): JSX.Element {
  return (
    <Bubble>
      <PersonaPollMessage
        poll={banPoll}
        direction="incoming"
        messageId="story-message-4"
        sendPollVote={sendPollVote}
      />
    </Bubble>
  );
}
