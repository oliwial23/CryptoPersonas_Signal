// Copyright 2019 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import classNames from 'classnames';
import lodash from 'lodash';
import { useCallback, useEffect, useMemo, useState } from 'react';
import type { ReactNode, ComponentProps, JSX, MouseEvent } from 'react';
import { createPortal } from 'react-dom';
import { Manager, Popper, Reference } from 'react-popper';
import type { PreventOverflowModifier } from '@popperjs/core/lib/modifiers/preventOverflow.js';
import { isDownloaded } from '../../util/Attachment.std.ts';
import type { LocalizerType } from '../../types/I18N.std.ts';
import { handleOutsideClick } from '../../util/handleOutsideClick.dom.ts';
import { offsetDistanceModifier } from '../../util/popperUtil.std.ts';
import { WidthBreakpoint } from '../_util.std.ts';
import { Message, MessageInteractivity } from './Message.dom.tsx';
import type { SmartReactionPicker } from '../../state/smart/ReactionPicker.dom.tsx';
import type {
  Props as MessageProps,
  PropsActions as MessagePropsActions,
  PropsData as MessagePropsData,
  PropsHousekeeping,
} from './Message.dom.tsx';
import type { PushPanelForConversationActionType } from '../../state/ducks/conversations.preload.ts';
import { doesMessageBodyOverflow } from './MessageBodyReadMore.dom.tsx';
import { useToggleReactionPicker } from '../../hooks/useKeyboardShortcuts.dom.tsx';
import { PanelType } from '../../types/Panels.std.ts';
import type {
  DeleteMessagesPropsType,
  ForwardMessagesPayload,
} from '../../state/ducks/globalModals.preload.ts';
import { useScrollerLock } from '../../hooks/useScrollLock.dom.tsx';
import { MessageContextMenu } from './MessageContextMenu.dom.tsx';
import { ForwardMessagesModalType } from '../ForwardMessagesModal.dom.tsx';
import { useGroupedAndOrderedReactions } from '../../util/groupAndOrderReactions.std.ts';
import { isNotNil } from '../../util/isNotNil.std.ts';
import type { AxoMenuBuilder } from '../../axo/AxoMenuBuilder.dom.tsx';
import { AxoContextMenu } from '../../axo/AxoContextMenu.dom.tsx';
import { useDocumentKeyDown } from '../../hooks/useDocumentKeyDown.dom.ts';
import { Emoji } from '../../axo/emoji.std.ts';
import { AxoConfirmDialog } from '../../axo/AxoConfirmDialog.dom.tsx';

const { useAxoContextMenuOutsideKeyboardTrigger } = AxoContextMenu;

const { noop } = lodash;

export type PropsData = {
  canDownload: boolean;
  canCopy: boolean;
  canEditMessage: boolean;
  canEndPoll: boolean;
  canForward: boolean;
  canRetry: boolean;
  canRetryDeleteForEveryone: boolean;
  canReact: boolean;
  canReply: boolean;
  canPinMessage: boolean;
  // Personas demo: do we hold Signal's group-admin role? Gates the revocation poll.
  canOpenPersonaBanPoll: boolean;
  selectedReaction?: Emoji.Variant;
  isTargeted?: boolean;
  isSignalConversation: boolean;
} & Omit<MessagePropsData, 'renderingContext' | 'menu'>;

export type PropsActions = {
  onPinnedMessageRemove: (messageId: string) => void;
  pushPanelForConversation: PushPanelForConversationActionType;
  toggleDeleteMessagesModal: (props: DeleteMessagesPropsType) => void;
  toggleForwardMessagesModal: (payload: ForwardMessagesPayload) => void;
  endPoll: (id: string) => void;
  // Personas demo: open a ban poll on this persona post.
  personaBanPoll: (id: string) => void;
  personaBanNow: (id: string) => void;
  reactToMessage: (
    id: string,
    { emoji, remove }: { emoji: Emoji.Variant; remove: boolean }
  ) => void;
  retryMessageSend: (id: string) => void;
  sendPollVote: (params: {
    messageId: string;
    optionIndexes: ReadonlyArray<number>;
  }) => void;
  copyMessageText: (id: string) => void;
  retryDeleteForEveryone: (id: string) => void;
  setMessageToEdit: (conversationId: string, messageId: string) => unknown;
  setQuoteByMessageId: (conversationId: string, messageId: string) => void;
  toggleSelectMessage: (
    conversationId: string,
    messageId: string,
    shift: boolean,
    selected: boolean
  ) => void;
  showPinMessageDialog: (
    messageId: string,
    isPinningDisappearingMessage: boolean
  ) => void;
  handleDebugMessage: () => void;
} & Omit<MessagePropsActions, 'onToggleSelect' | 'onReplyToMessage'>;

export type Props = PropsData &
  PropsActions &
  Omit<PropsHousekeeping, 'isAttachmentPending'> & {
    renderReactionPicker: (
      props: ComponentProps<typeof SmartReactionPicker>
    ) => JSX.Element;
  };

/**
 * Message with menu/context-menu (as necessary for rendering in the timeline)
 */
export function TimelineMessage(props: Props): JSX.Element {
  const {
    attachments,
    canDownload,
    canCopy,
    canEditMessage,
    canEndPoll,
    canForward,
    canReact,
    canReply,
    canRetry,
    canRetryDeleteForEveryone,
    canPinMessage,
    canOpenPersonaBanPoll,
    containerElementRef,
    containerWidthBreakpoint,
    conversationId,
    direction,
    i18n,
    id,
    interactivity,
    isPinned,
    isSignalConversation,
    isTargeted,
    kickOffAttachmentDownload,
    copyMessageText,
    endPoll,
    personaBanPoll,
    personaBanNow,
    personaEh,
    personaPoll,
    expirationLength,
    handleDebugMessage,
    onPinnedMessageRemove,
    pushPanelForConversation,
    reactToMessage,
    renderReactionPicker,
    retryDeleteForEveryone,
    retryMessageSend,
    saveAttachment,
    saveAttachments,
    showAttachmentDownloadStillInProgressToast,
    showPinMessageDialog,
    selectedReaction,
    setQuoteByMessageId,
    setMessageToEdit,
    text,
    timestamp,
    toggleDeleteMessagesModal,
    toggleForwardMessagesModal,
    toggleSelectMessage,
  } = props;

  const [reactionPickerRoot, setReactionPickerRoot] = useState<
    HTMLDivElement | undefined
  >(undefined);

  const isWindowWidthNotNarrow =
    containerWidthBreakpoint !== WidthBreakpoint.Narrow;

  const popperPreventOverflowModifier =
    useCallback((): Partial<PreventOverflowModifier> => {
      return {
        name: 'preventOverflow',
        options: {
          altAxis: true,
          boundary: containerElementRef.current || undefined,
          padding: {
            bottom: 16,
            left: 8,
            right: 8,
            top: 16,
          },
        },
      };
    }, [containerElementRef]);

  const toggleReactionPicker = useCallback(
    (onlyRemove = false): void => {
      if (reactionPickerRoot) {
        document.body.removeChild(reactionPickerRoot);
        setReactionPickerRoot(undefined);
        return;
      }

      if (!onlyRemove) {
        const root = document.createElement('div');
        document.body.appendChild(root);

        setReactionPickerRoot(root);
      }
    },
    [reactionPickerRoot]
  );

  useScrollerLock({
    reason: 'TimelineMessage reactionPicker',
    lockScrollWhen: reactionPickerRoot != null,
    onUserInterrupt() {
      toggleReactionPicker(true);
    },
  });

  useEffect(() => {
    let cleanUpHandler: (() => void) | undefined;
    if (reactionPickerRoot) {
      cleanUpHandler = handleOutsideClick(
        target => {
          if (
            target instanceof Element &&
            target.closest('[data-fun-overlay]') != null
          ) {
            return true;
          }
          toggleReactionPicker(true);
          return true;
        },
        {
          containerElements: [reactionPickerRoot],
          name: 'Message.reactionPicker',
        }
      );
    }
    return () => {
      cleanUpHandler?.();
    };
  });

  const openGenericAttachment = useCallback(
    (event?: MouseEvent): void => {
      if (event) {
        event.preventDefault();
        event.stopPropagation();
      }

      if (!attachments || attachments.length === 0) {
        return;
      }

      let attachmentsInProgress = 0;
      // check if any attachment needs to be downloaded from servers
      for (const attachment of attachments) {
        if (!isDownloaded(attachment)) {
          kickOffAttachmentDownload({ messageId: id });

          attachmentsInProgress += 1;
        }
      }

      if (attachmentsInProgress !== 0) {
        showAttachmentDownloadStillInProgressToast(attachmentsInProgress);
      }

      if (attachments.length !== 1) {
        saveAttachments(attachments, timestamp);
      } else {
        // oxlint-disable-next-line typescript/no-non-null-assertion
        saveAttachment(attachments[0]!, timestamp);
      }
    },
    [
      kickOffAttachmentDownload,
      saveAttachments,
      saveAttachment,
      showAttachmentDownloadStillInProgressToast,
      attachments,
      id,
      timestamp,
    ]
  );

  const shouldShowAdditional =
    doesMessageBodyOverflow(text || '') || !isWindowWidthNotNarrow;

  const canSelect = interactivity === MessageInteractivity.Normal;

  const handleDownload = canDownload ? openGenericAttachment : null;

  const handleReplyToMessage = useCallback(() => {
    if (!canReply) {
      return;
    }
    setQuoteByMessageId(conversationId, id);
  }, [canReply, conversationId, id, setQuoteByMessageId]);


  const handleReact = useCallback(() => {
    if (canReact) {
      toggleReactionPicker();
    }
  }, [canReact, toggleReactionPicker]);

  const isDisappearingMessage = expirationLength != null;

  const handleOpenPinMessageDialog = useCallback(() => {
    showPinMessageDialog(id, isDisappearingMessage);
  }, [showPinMessageDialog, id, isDisappearingMessage]);

  const handleUnpinMessage = useCallback(() => {
    onPinnedMessageRemove(id);
  }, [onPinnedMessageRemove, id]);

  const toggleReactionPickerKeyboard = useToggleReactionPicker(
    handleReact || noop
  );

  useDocumentKeyDown(event => {
    if (isTargeted) {
      toggleReactionPickerKeyboard(event);
    }
  });

  const groupedReactions = useGroupedAndOrderedReactions(
    props.reactions,
    'variant'
  );

  const messageEmojis = useMemo(() => {
    return groupedReactions
      .map(groupedReaction => {
        return groupedReaction?.[0]?.variant;
      })
      .filter(isNotNil);
  }, [groupedReactions]);

  const renderMessageContextMenu = useCallback(
    (renderer: AxoMenuBuilder.Renderer, children: ReactNode): JSX.Element => {
      return (
        <MessageContextMenu
          i18n={i18n}
          renderer={renderer}
          shouldShowAdditional={shouldShowAdditional}
          onDownload={handleDownload}
          onEdit={
            canEditMessage ? () => setMessageToEdit(conversationId, id) : null
          }
          onReplyToMessage={handleReplyToMessage}
          // Gated on `canReact` to match the hover menu below.
          //
          // The reaction picker is a <Popper> that anchors to a <Reference> living
          // INSIDE the hover menu's react button, and that button is rendered only when
          // `canReact` is true. Offering "React" here unconditionally therefore made it
          // possible to open the picker while its anchor did not exist, and react-popper
          // falls back to the viewport origin — the picker appeared in the top-left
          // corner of the window, next to the traffic lights, instead of over the
          // message.
          //
          // Not a personas bug, but personas made it reachable: `canReact` is false for
          // your own outgoing persona posts (see canReplyOrReact — the outgoing branch
          // needs a recipient in `isSent` state, which a phantom-routed send does not
          // record the usual way), so this path was hit routinely for the first time.
          onReact={canReact ? handleReact : null}
          onEndPoll={canEndPoll ? () => endPoll(id) : null}
          // Personas demo: offered only on a persona POST (something with an
          // envelope hash to target) and never on a poll — you cannot open a
          // revocation poll about a poll.
          // Personas demo: offered only on a persona POST (something with an envelope
          // hash to target), never on a poll, and now only to a Signal group ADMIN.
          //
          // The gate leaks nothing by itself: a ban poll still rides the shared phantom,
          // so the record on the wire is byte-identical and no recipient learns who
          // opened it. What the gate costs is subtler and worth stating — if in practice
          // only admins open ban polls, then an observer who knows the admin set can
          // INFER the opener from the poll's existence. With a single admin, a ban poll
          // identifies them. That is an inference leak, not a data leak, and it is the
          // anonymity this trade actually spends.
          //
          // It is also NOT enforcement. Persona records are ordinary message bodies the
          // storage-service never inspects, so a modified client ignores this check
          // entirely and can open a ban poll regardless. Real enforcement needs the
          // moderator credential inside the proof — that is what badges are for
          // (PERSONAS_SERVERLESS_TODO.md section 2).
          // ANY member may request a poll: it only asks the group. Previously this was
          // admin-gated, which left ordinary members with no way to flag a post at all.
          isPersonaPost={personaEh != null && personaPoll == null}
          onPersonaBanPoll={
            personaEh != null && personaPoll == null
              ? () => personaBanPoll(id)
              : null
          }
          // Admin-only. Same target conditions, plus the Signal group-admin role —
          // this is the one that actually carries, so it is the one that is gated.
          onPersonaBanNow={
            personaEh != null && personaPoll == null && canOpenPersonaBanPoll
              ? () => setIsConfirmingBan(true)
              : null
          }
          onRetryMessageSend={canRetry ? () => retryMessageSend(id) : null}
          onRetryDeleteForEveryone={
            canRetryDeleteForEveryone ? () => retryDeleteForEveryone(id) : null
          }
          onCopy={canCopy ? () => copyMessageText(id) : null}
          onSelect={
            canSelect
              ? () => toggleSelectMessage(conversationId, id, false, true)
              : null
          }
          onForward={
            canForward
              ? () =>
                  toggleForwardMessagesModal({
                    type: ForwardMessagesModalType.Forward,
                    messageIds: [id],
                  })
              : null
          }
          onDeleteMessage={() => {
            toggleDeleteMessagesModal({
              conversationId,
              messageIds: [id],
            });
          }}
          onPinMessage={
            canPinMessage && !isPinned ? handleOpenPinMessageDialog : null
          }
          onUnpinMessage={canPinMessage && isPinned ? handleUnpinMessage : null}
          onMoreInfo={() =>
            pushPanelForConversation({
              type: PanelType.MessageDetails,
              args: { messageId: id },
            })
          }
          onDebugMessage={handleDebugMessage}
        >
          {children}
        </MessageContextMenu>
      );
    },
    [
      canCopy,
      canEditMessage,
      canForward,
      canPinMessage,
      canOpenPersonaBanPoll,
      canReact,
      canRetry,
      canSelect,
      canEndPoll,
      canRetryDeleteForEveryone,
      conversationId,
      personaBanPoll,
      personaBanNow,
      personaEh,
      personaPoll,
      copyMessageText,
      handleDebugMessage,
      handleDownload,
      handleReact,
      handleOpenPinMessageDialog,
      handleUnpinMessage,
      endPoll,
      handleReplyToMessage,
      i18n,
      id,
      isPinned,
      pushPanelForConversation,
      retryDeleteForEveryone,
      retryMessageSend,
      setMessageToEdit,
      shouldShowAdditional,
      toggleDeleteMessagesModal,
      toggleForwardMessagesModal,
      toggleSelectMessage,
    ]
  );

  // THE REACTION PICKER'S ANCHOR.
  //
  // Held in state rather than a ref so that attaching it re-renders the <Popper>; a
  // plain ref would be populated after the popper had already positioned itself
  // against nothing.
  //
  // Why not <Reference>: the picker is positioned by react-popper from whichever
  // <Reference> is mounted inside the <Manager>, and those live inside individual
  // hover buttons that come and go with window width and with `canReact`. Two separate
  // attempts to cover every combination still left the picker unanchored in practice,
  // and an unanchored popper is placed at viewport 0,0 — the top-left corner of the
  // window, overlapping the close button. Passing `referenceElement` explicitly removes
  // the whole question: the anchor is the buttons container, which is always mounted.
  const [menuElement, setMenuElement] = useState<HTMLDivElement | null>(null);

  const renderMenu = useCallback(() => {
    return (
      <Manager>
        <MessageMenu
          rootRef={setMenuElement}
          i18n={i18n}
          isWindowWidthNotNarrow={isWindowWidthNotNarrow}
          direction={direction}
          onDownload={handleDownload}
          onReplyToMessage={canReply ? handleReplyToMessage : null}
          onReact={canReact ? handleReact : null}
          renderMessageContextMenu={renderMessageContextMenu}
        />
        {reactionPickerRoot &&
          createPortal(
            <Popper
              placement="top"
              // Explicit anchor — see `menuElement`. `?? undefined` so that before the
              // container has mounted we fall back to react-popper's own <Reference>
              // lookup rather than passing null and anchoring to nothing.
              referenceElement={menuElement ?? undefined}
              modifiers={[
                offsetDistanceModifier(4),
                popperPreventOverflowModifier(),
              ]}
            >
              {({ ref, style }) =>
                renderReactionPicker({
                  ref,
                  style,
                  selected: selectedReaction,
                  onClose: toggleReactionPicker,
                  onPick: emoji => {
                    toggleReactionPicker(true);
                    reactToMessage(id, {
                      emoji,
                      remove: emoji === selectedReaction,
                    });
                  },
                  messageEmojis,
                })
              }
            </Popper>,
            reactionPickerRoot
          )}
      </Manager>
    );
  }, [
    menuElement,
    i18n,
    isWindowWidthNotNarrow,
    direction,
    canReply,
    canReact,
    handleDownload,
    handleReplyToMessage,
    handleReact,
    reactionPickerRoot,
    popperPreventOverflowModifier,
    renderReactionPicker,
    selectedReaction,
    reactToMessage,
    toggleReactionPicker,
    id,
    messageEmojis,
    renderMessageContextMenu,
  ]);

  // CONFIRMATION FOR A PERMANENT BAN.
  //
  // The other destructive persona action, "Request ban poll", is reversible — the group
  // votes and may decline. A permanent ban is not: once the poll closes the callback is
  // invoked, and the target's next scan writes `banned` into their object. There is no
  // unban in this protocol. A menu item one slip of the mouse away from that deserves a
  // stop.
  //
  // Deliberately NOT applied to the poll request: a confirmation on a harmless, common
  // action is the kind of friction that teaches people to click through dialogs without
  // reading them, which would weaken this one.
  const [isConfirmingBan, setIsConfirmingBan] = useState(false);
  const handleConfirmBan = useCallback(() => {
    setIsConfirmingBan(false);
    personaBanNow(id);
  }, [id, personaBanNow]);

  const handleWrapperKeyDown = useAxoContextMenuOutsideKeyboardTrigger();

  return (
    <>
      <AxoConfirmDialog.Root
        open={isConfirmingBan}
        onOpenChange={setIsConfirmingBan}
        title="Ban this author permanently?"
        description={
          'You are about to ban this user. They will lose anonymous and pseudonymous ' +
          'posting in this group and will only be able to send messages under their ' +
          'real identity here. It takes effect within a few seconds, with no poll, and ' +
          'cannot be undone. The group will see that you issued it; who wrote the post ' +
          'stays hidden. Do you want to proceed?'
        }
      >
        <AxoConfirmDialog.Cancel />
        <AxoConfirmDialog.Action
          variant="strong-primary"
          onClick={handleConfirmBan}
        >
          Ban permanently
        </AxoConfirmDialog.Action>
      </AxoConfirmDialog.Root>
    <Message
      {...props}
      renderingContext="conversation/TimelineItem"
      renderMenu={isSignalConversation ? undefined : renderMenu}
      renderMessageContextMenu={renderMessageContextMenu}
      onToggleSelect={(selected, shift) => {
        toggleSelectMessage(conversationId, id, shift, selected);
      }}
      onReplyToMessage={handleReplyToMessage}
      onWrapperKeyDown={handleWrapperKeyDown}
    />
    </>
  );
}

type MessageMenuProps = {
  i18n: LocalizerType;
  isWindowWidthNotNarrow: boolean;
  onDownload: (() => void) | null;
  onReplyToMessage: (() => void) | null;
  onReact: (() => void) | null;
  renderMessageContextMenu: (
    renderer: AxoMenuBuilder.Renderer,
    children: ReactNode
  ) => ReactNode;
  /** Callback ref for the buttons container, used as the reaction picker's anchor. */
  rootRef: (element: HTMLDivElement | null) => void;
} & Pick<MessageProps, 'i18n' | 'direction'>;

function MessageMenu({
  i18n,
  direction,
  isWindowWidthNotNarrow,
  onDownload,
  onReplyToMessage,
  onReact,
  renderMessageContextMenu,
  rootRef,
}: MessageMenuProps) {
  return (
    <div
      // The picker anchors to THIS element. See the note on `menuElement` above: the
      // per-button <Reference> approach kept leaving the popper unanchored, and an
      // unanchored popper lands at viewport 0,0 — the window's top-left corner, next
      // to the traffic lights. This container is always mounted (it is only
      // `opacity: 0` until hover, per _modules.scss) and always has a real box next to
      // the message, so anchoring to it is correct in every state.
      ref={rootRef}
      className={classNames(
        'module-message__buttons',
        `module-message__buttons--${direction}`
      )}
    >
      {isWindowWidthNotNarrow && (
        <>
          {onReact && (
            <Reference>
              {({ ref: popperRef }) => {
                // Only attach the popper reference to the reaction button if it is
                //   visible (it is hidden when the timeline is narrow)
                const maybePopperRef = isWindowWidthNotNarrow
                  ? popperRef
                  : undefined;

                return (
                  // FIXME: Menus should be keyboard accessible
                  // oxlint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/interactive-supports-focus
                  <div
                    ref={maybePopperRef}
                    onClick={(event: MouseEvent) => {
                      event.stopPropagation();
                      event.preventDefault();

                      onReact();
                    }}
                    role="button"
                    className="module-message__buttons__react"
                    aria-label={i18n('icu:reactToMessage')}
                    onDoubleClick={ev => {
                      // Prevent double click from triggering the replyToMessage action
                      ev.stopPropagation();
                    }}
                  />
                );
              }}
            </Reference>
          )}

          {onDownload && (
            // FIXME: Menus should be keyboard accessible
            // oxlint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/interactive-supports-focus
            <div
              onClick={onDownload}
              role="button"
              aria-label={i18n('icu:downloadAttachment')}
              className={classNames(
                'module-message__buttons__download',
                `module-message__buttons__download--${direction}`
              )}
              onDoubleClick={ev => {
                // Prevent double click from triggering the replyToMessage action
                ev.stopPropagation();
              }}
            />
          )}

          {onReplyToMessage && (
            // FIXME: Menus should be keyboard accessible
            // oxlint-disable-next-line jsx-a11y/click-events-have-key-events, jsx-a11y/interactive-supports-focus
            <div
              onClick={(event: MouseEvent) => {
                event.stopPropagation();
                event.preventDefault();

                onReplyToMessage();
              }}
              role="button"
              aria-label={i18n('icu:replyToMessage')}
              className={classNames(
                'module-message__buttons__reply',
                `module-message__buttons__download--${direction}`
              )}
              onDoubleClick={ev => {
                // Prevent double click from triggering the replyToMessage action
                ev.stopPropagation();
              }}
            />
          )}
        </>
      )}
      <Reference>
        {({ ref: popperRef }) => {
          // Attach the popper reference to the collapsed menu button whenever the
          // REACT BUTTON is not the one carrying it.
          //
          // Upstream only checked the width: narrow => anchor here, wide => anchor on
          // the react button. That leaves one combination with NO anchor at all —
          // wide window, but `onReact` falsy, so the react button (and the <Reference>
          // inside it) never renders. react-popper then falls back to the viewport
          // origin and the picker appears in the top-left corner of the window, over
          // the traffic lights.
          //
          // Upstream never hits it because `onReact` is effectively always set for a
          // reactable message. Personas made it ordinary: `canReact` is false for your
          // own outgoing persona posts (canReplyOrReact's outgoing branch wants a
          // recipient in `isSent` state, which a phantom-routed send does not record
          // the usual way), so wide + no-react is a normal state here.
          //
          // Testing both conditions makes the anchor unconditional across all four
          // combinations of width and react-ability, rather than three of them.
          const maybePopperRef =
            !isWindowWidthNotNarrow || !onReact ? popperRef : undefined;

          return renderMessageContextMenu(
            'AxoDropdownMenu',
            <button
              ref={maybePopperRef}
              type="button"
              aria-label={i18n('icu:messageContextMenuButton')}
              className={classNames(
                'module-message__buttons__menu',
                `module-message__buttons__download--${direction}`
              )}
              onDoubleClick={ev => {
                // Prevent double click from triggering the replyToMessage action
                ev.stopPropagation();
              }}
            />
          );
        }}
      </Reference>
    </div>
  );
}
