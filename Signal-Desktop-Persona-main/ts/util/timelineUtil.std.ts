// Copyright 2022 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import lodash from 'lodash';
import { createLogger } from '../logging/log.std.ts';
// oxlint-disable-next-line signal-desktop/no-restricted-paths
import type { PropsType as TimelinePropsType } from '../components/conversation/Timeline.dom.tsx';
// oxlint-disable-next-line signal-desktop/no-restricted-paths
import type { TimelineItemType } from '../components/conversation/TimelineItem.dom.tsx';
// oxlint-disable-next-line signal-desktop/no-restricted-paths
import { WidthBreakpoint } from '../components/_util.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { MINUTE } from './durations/index.std.ts';
import { missingCaseError } from './missingCaseError.std.ts';
import { isSameDay } from './timestamp.std.ts';
import type { LastMessageStatus } from '../model-types.d.ts';

const { isNumber } = lodash;

const log = createLogger('timelineUtil');

const COLLAPSE_WITHIN = 3 * MINUTE;

export enum TimelineMessageLoadingState {
  // We start the enum at 1 because the default starting value of 0 is falsy.
  DoingInitialLoad = 1,
  LoadingOlderMessages,
  LoadingNewerMessages,
}

export enum ScrollAnchor {
  ChangeNothing,
  ScrollToBottom,
  ScrollToIndex,
  ScrollToUnreadIndicator,
  Top,
  Bottom,
}

export enum UnreadIndicatorPlacement {
  JustAbove,
  JustBelow,
}

export type MessageTimelineItemDataType = Readonly<{
  author: { id: string };
  deletedForEveryone?: boolean;
  isEditedMessage?: boolean;
  reactions?: ReadonlyArray<unknown>;
  status?: LastMessageStatus;
  timestamp: number;
  // Personas demo: the persona a post was made under. Two adjacent posts from the
  // same account but different personas must not visually group, so each shows its
  // own persona label.
  persona?: string;
  // Personas demo: the context this message was posted into, if any. Used to chain
  // consecutive messages in one context — see `areMessagesInSameContext`.
  personaContextName?: string;
}>;

// This lets us avoid passing a full `MessageType`. That's useful for tests and for
//   documentation.
export type MaybeMessageTimelineItemType = Readonly<
  | undefined
  | TimelineItemType
  | { type: 'message'; data: MessageTimelineItemDataType }
>;

const getMessageTimelineItemData = (
  timelineItem: MaybeMessageTimelineItemType
): undefined | MessageTimelineItemDataType =>
  timelineItem?.type === 'message' ? timelineItem.data : undefined;

export function shouldCurrentMessageHideMetadata(
  areMessagesGrouped: boolean,
  item: MaybeMessageTimelineItemType,
  newerTimelineItem: MaybeMessageTimelineItemType
): boolean {
  if (!areMessagesGrouped) {
    return false;
  }

  const message = getMessageTimelineItemData(item);
  if (!message) {
    return false;
  }

  if (message.isEditedMessage) {
    return false;
  }

  const newerMessage = getMessageTimelineItemData(newerTimelineItem);
  if (!newerMessage) {
    return false;
  }

  // If newer message is deleted, but current isn't, we'll show metadata.
  if (newerMessage.deletedForEveryone && !message.deletedForEveryone) {
    return false;
  }

  switch (message.status) {
    case undefined:
      return true;
    case 'paused':
    case 'error':
    case 'partial-sent':
    case 'sending':
      return false;
    case 'sent':
    case 'delivered':
    case 'read':
    case 'viewed':
      return true;
    default:
      log.error(toLogFormat(missingCaseError(message.status)));
      return true;
  }
}

export function areMessagesInSameGroup(
  olderTimelineItem: MaybeMessageTimelineItemType,
  unreadIndicator: boolean,
  newerTimelineItem: MaybeMessageTimelineItemType
): boolean {
  if (unreadIndicator) {
    return false;
  }

  const olderMessage = getMessageTimelineItemData(olderTimelineItem);
  if (!olderMessage) {
    return false;
  }

  const newerMessage = getMessageTimelineItemData(newerTimelineItem);
  if (!newerMessage) {
    return false;
  }

  return (
    !olderMessage.reactions?.length &&
    olderMessage.author.id === newerMessage.author.id &&
    // Personas demo: only group posts made under the same persona (undefined ===
    // undefined groups ordinary messages as before; different personas never group).
    olderMessage.persona === newerMessage.persona &&
    (olderMessage.isEditedMessage ||
      newerMessage.timestamp >= olderMessage.timestamp) &&
    newerMessage.timestamp - olderMessage.timestamp < COLLAPSE_WITHIN &&
    isSameDay(olderMessage.timestamp, newerMessage.timestamp)
  );
}

/**
 * Personas demo: do two adjacent messages belong to the same CONTEXT?
 *
 * Deliberately a much weaker test than `areMessagesInSameGroup`, because it answers a
 * different question. Grouping asks "is this the same speaker continuing?" — so it
 * requires the same author, the same persona, and closeness in time. A context chain
 * asks "do these belong to the same conversation?", and the entire point of a context
 * is that SEVERAL personas post into it. So this ignores author, persona, reactions and
 * elapsed time, and compares only the context name.
 *
 * Consequence worth knowing: a chain stays unbroken across a day divider and across
 * speakers, which is correct — the context genuinely continues — but it means a chain
 * can span a long gap. That is the grouping the advisors asked to be able to see.
 */
export function areMessagesInSameContext(
  olderTimelineItem: MaybeMessageTimelineItemType,
  newerTimelineItem: MaybeMessageTimelineItemType
): boolean {
  const older = getMessageTimelineItemData(olderTimelineItem);
  const newer = getMessageTimelineItemData(newerTimelineItem);
  if (!older || !newer) {
    return false;
  }
  // Both must actually HAVE a context: two messages with no context are not a chain,
  // and `undefined === undefined` would otherwise link every ordinary message.
  return Boolean(
    older.personaContextName &&
    newer.personaContextName &&
    older.personaContextName === newer.personaContextName
  );
}

type ScrollAnchorBeforeUpdateProps = Readonly<
  Pick<
    TimelinePropsType,
    | 'haveNewest'
    | 'isIncomingMessageRequest'
    | 'isSomeoneTyping'
    | 'items'
    | 'messageLoadingState'
    | 'oldestUnseenIndex'
    | 'scrollToIndex'
    | 'scrollToIndexCounter'
  >
>;

export function getScrollAnchorBeforeUpdate(
  prevProps: ScrollAnchorBeforeUpdateProps,
  props: ScrollAnchorBeforeUpdateProps,
  isAtBottom: boolean
): ScrollAnchor {
  if (props.messageLoadingState || !props.items.length) {
    return ScrollAnchor.ChangeNothing;
  }

  const loadingStateThatJustFinished: undefined | TimelineMessageLoadingState =
    !props.messageLoadingState && prevProps.messageLoadingState
      ? prevProps.messageLoadingState
      : undefined;

  if (
    isNumber(props.scrollToIndex) &&
    (loadingStateThatJustFinished ===
      TimelineMessageLoadingState.DoingInitialLoad ||
      prevProps.scrollToIndex !== props.scrollToIndex ||
      prevProps.scrollToIndexCounter !== props.scrollToIndexCounter)
  ) {
    return ScrollAnchor.ScrollToIndex;
  }

  switch (loadingStateThatJustFinished) {
    case TimelineMessageLoadingState.DoingInitialLoad:
      if (props.isIncomingMessageRequest) {
        return ScrollAnchor.ChangeNothing;
      }
      if (isNumber(props.oldestUnseenIndex)) {
        return ScrollAnchor.ScrollToUnreadIndicator;
      }
      return ScrollAnchor.ScrollToBottom;
    case TimelineMessageLoadingState.LoadingOlderMessages:
      return ScrollAnchor.Bottom;
    case TimelineMessageLoadingState.LoadingNewerMessages:
      return ScrollAnchor.Top;
    case undefined: {
      const didSomethingChange =
        prevProps.items.length !== props.items.length ||
        (props.haveNewest &&
          prevProps.isSomeoneTyping !== props.isSomeoneTyping);
      if (didSomethingChange && isAtBottom) {
        return ScrollAnchor.ScrollToBottom;
      }
      break;
    }
    default:
      throw missingCaseError(loadingStateThatJustFinished);
  }

  return ScrollAnchor.ChangeNothing;
}

export function getWidthBreakpoint(width: number): WidthBreakpoint {
  if (width > 606) {
    return WidthBreakpoint.Wide;
  }
  if (width > 514) {
    return WidthBreakpoint.Medium;
  }
  return WidthBreakpoint.Narrow;
}
