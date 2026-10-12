// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import { useRef, type ReactNode, type JSX } from 'react';
import type { LocalizerType } from '../../types/I18N.std.ts';
import { AxoMenuBuilder } from '../../axo/AxoMenuBuilder.dom.tsx';
import { isInternalFeaturesEnabled } from '../../util/isInternalFeaturesEnabled.dom.ts';

type MessageContextMenuProps = Readonly<{
  i18n: LocalizerType;
  renderer: AxoMenuBuilder.Renderer;
  onOpenChange?: (open: boolean) => void;
  disabled?: boolean;
  shouldShowAdditional: boolean;
  onDebugMessage: (() => void) | null;
  onDownload: (() => void) | null;
  onEdit: (() => void) | null;
  onReplyToMessage: (() => void) | null;
  onReact: (() => void) | null;
  onEndPoll: (() => void) | null;
  // Personas demo: open a ban poll on this persona post. Optional, not just
  // nullable, so the menu's other call sites (CallingNotification, CollapseSet) —
  // which can never be showing a persona post — do not have to know about it.
  onPersonaBanPoll?: (() => void) | null;
  onPersonaBanNow?: (() => void) | null;
  /** This is a persona post, so the thumbs carry a reputation vote. */
  isPersonaPost?: boolean;
  onRetryMessageSend: (() => void) | null;
  onRetryDeleteForEveryone: (() => void) | null;
  onCopy: (() => void) | null;
  onForward: (() => void) | null;
  onDeleteMessage: (() => void) | null;
  onPinMessage: (() => void) | null;
  onUnpinMessage: (() => void) | null;
  onMoreInfo: (() => void) | null;
  onSelect: (() => void) | null;
  children: ReactNode;
}>;

export function MessageContextMenu({
  i18n,
  renderer,
  onOpenChange,
  disabled,
  shouldShowAdditional,
  onDebugMessage,
  onDownload,
  onEdit,
  onReplyToMessage,
  onReact,
  onEndPoll,
  onPersonaBanPoll,
  onPersonaBanNow,
  isPersonaPost,
  onMoreInfo,
  onCopy,
  onSelect,
  onRetryMessageSend,
  onRetryDeleteForEveryone,
  onForward,
  onDeleteMessage,
  onPinMessage,
  onUnpinMessage,
  children,
}: MessageContextMenuProps): JSX.Element {
  const shouldReturnFocusToTrigger = useRef(true);

  return (
    <AxoMenuBuilder.Root renderer={renderer} onOpenChange={onOpenChange}>
      <AxoMenuBuilder.Trigger disabled={disabled}>
        {children}
      </AxoMenuBuilder.Trigger>
      <AxoMenuBuilder.Content
        onCloseAutoFocus={e => {
          if (!shouldReturnFocusToTrigger.current) {
            e.preventDefault();
          }
        }}
      >
        {shouldShowAdditional && (
          <>
            {onDownload && (
              <AxoMenuBuilder.Item symbol="download" onSelect={onDownload}>
                {i18n('icu:MessageContextMenu__download')}
              </AxoMenuBuilder.Item>
            )}
            {onReplyToMessage && (
              <AxoMenuBuilder.Item
                symbol="reply"
                onSelect={() => {
                  // onReplyToMessage will focus the quill input
                  shouldReturnFocusToTrigger.current = false;
                  onReplyToMessage();
                }}
              >
                {i18n('icu:MessageContextMenu__reply')}
              </AxoMenuBuilder.Item>
            )}
            {onReact && (
              <AxoMenuBuilder.Item symbol="heart-plus" onSelect={onReact}>
                {/* On a persona post the thumbs are not decoration: they emit the
                    protocol's Rate record and move the author's reputation, while every
                    other emoji is refused outright (an attributable reaction would
                    reveal who reacted). Saying so HERE means the user knows before
                    opening the picker rather than guessing from six equal-looking
                    emoji — and it needs no change to Signal's own picker component. */}
                {isPersonaPost
                  ? `${i18n('icu:MessageContextMenu__react')} — 👍 upvote / 👎 downvote`
                  : i18n('icu:MessageContextMenu__react')}
              </AxoMenuBuilder.Item>
            )}
          </>
        )}
        {onEndPoll && (
          <AxoMenuBuilder.Item symbol="stop-circle" onSelect={onEndPoll}>
            {i18n('icu:Poll__end-poll')}
          </AxoMenuBuilder.Item>
        )}
        {/* Personas demo: put this persona up for revocation. Deliberately worded
            about the PERSONA, not the person — the persona is the only thing anyone
            in the group is entitled to know about the author. */}
        {/* `block`, not `person-x`: the person-* ban glyphs live in
            AxoSymbolInlineGlyphOnlyName and are not valid AxoSymbolIconName values,
            which is what a menu Item takes. `block` is what Signal's own "Block"
            menu item uses. */}
        {/* "Ban author…" rather than "Open revocation poll": an admin looking for a way
            to ban someone searches for the word ban, and the old label hid the feature
            from the person it was built for. The trailing ellipsis is doing real work —
            it signals that this STARTS something rather than finishing it, because the
            protocol has no unilateral ban. A ban exists only as a poll that settles at
            a barrier, so one admin click cannot remove anyone by itself. */}
        {/* TWO distinct actions, deliberately not one.
            "Request ban poll" is open to every member: anyone may raise a post for the
            group to judge. It opens the poll and casts nothing, so a request is never
            misreported as a verdict.
            "Ban permanently" is admin-only and also casts the admin's Ban ballot, which
            is what makes the poll carry at its close barrier and actually revoke the
            author's persona privileges. The wording says "permanently" because that is
            the user-visible effect; the honest caveat (a Keep vote can still cancel it)
            lives in sendPersonaBanPoll's doc comment and in the workplan. */}
        {onPersonaBanPoll && (
          <AxoMenuBuilder.Item symbol="block" onSelect={onPersonaBanPoll}>
            Request ban poll…
          </AxoMenuBuilder.Item>
        )}
        {onPersonaBanNow && (
          <AxoMenuBuilder.Item symbol="block" onSelect={onPersonaBanNow}>
            Ban permanently (admin)
          </AxoMenuBuilder.Item>
        )}
        {onForward && (
          <AxoMenuBuilder.Item
            symbol="forward"
            onSelect={() => {
              // forward modal takes focus
              shouldReturnFocusToTrigger.current = false;
              onForward();
            }}
          >
            {i18n('icu:MessageContextMenu__forward')}
          </AxoMenuBuilder.Item>
        )}
        {onEdit && (
          <AxoMenuBuilder.Item
            symbol="pencil"
            onSelect={() => {
              // onEdit will focus the quill input
              shouldReturnFocusToTrigger.current = false;
              onEdit();
            }}
          >
            {i18n('icu:edit')}
          </AxoMenuBuilder.Item>
        )}
        {onSelect && (
          <AxoMenuBuilder.Item symbol="check-circle" onSelect={onSelect}>
            {i18n('icu:MessageContextMenu__select')}
          </AxoMenuBuilder.Item>
        )}
        {onCopy && (
          <AxoMenuBuilder.Item symbol="copy" onSelect={onCopy}>
            {i18n('icu:copy')}
          </AxoMenuBuilder.Item>
        )}
        {onPinMessage && (
          <AxoMenuBuilder.Item symbol="pin" onSelect={onPinMessage}>
            {i18n('icu:MessageContextMenu__PinMessage')}
          </AxoMenuBuilder.Item>
        )}
        {onUnpinMessage && (
          <AxoMenuBuilder.Item symbol="pin-slash" onSelect={onUnpinMessage}>
            {i18n('icu:MessageContextMenu__UnpinMessage')}
          </AxoMenuBuilder.Item>
        )}
        {onMoreInfo && (
          <AxoMenuBuilder.Item symbol="info" onSelect={onMoreInfo}>
            {i18n('icu:MessageContextMenu__info')}
          </AxoMenuBuilder.Item>
        )}
        {onDeleteMessage && (
          <AxoMenuBuilder.Item symbol="trash" onSelect={onDeleteMessage}>
            {i18n('icu:MessageContextMenu__deleteMessage')}
          </AxoMenuBuilder.Item>
        )}
        {onRetryMessageSend && (
          <AxoMenuBuilder.Item symbol="send" onSelect={onRetryMessageSend}>
            {i18n('icu:retrySend')}
          </AxoMenuBuilder.Item>
        )}
        {onRetryDeleteForEveryone && (
          <AxoMenuBuilder.Item
            symbol="trash"
            onSelect={onRetryDeleteForEveryone}
          >
            {i18n('icu:retryDeleteForEveryone')}
          </AxoMenuBuilder.Item>
        )}
        {isInternalFeaturesEnabled() && onDebugMessage && (
          <>
            <AxoMenuBuilder.Separator />
            <AxoMenuBuilder.Group>
              <AxoMenuBuilder.Label>Internal</AxoMenuBuilder.Label>
              <AxoMenuBuilder.Item symbol="copy" onSelect={onDebugMessage}>
                Copy & debug message
              </AxoMenuBuilder.Item>
            </AxoMenuBuilder.Group>
          </>
        )}
      </AxoMenuBuilder.Content>
    </AxoMenuBuilder.Root>
  );
}
