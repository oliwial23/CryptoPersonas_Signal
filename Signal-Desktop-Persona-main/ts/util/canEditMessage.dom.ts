// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

import type { ReadonlyMessageAttributesType } from '../model-types.d.ts';
import { DAY } from './durations/index.std.ts';
import { isMoreRecentThan } from './timestamp.std.ts';
import { isOutgoing, isPoll } from '../messages/helpers.std.ts';
import { isMessageNoteToSelf } from './isMessageNoteToSelf.dom.ts';

export const MESSAGE_MAX_EDIT_COUNT = 10;

export function canEditMessage(
  message: ReadonlyMessageAttributesType
): boolean {
  return (
    !message.sms &&
    !message.deletedForEveryone &&
    isOutgoing(message) &&
    !isPoll(message) &&
    // Personas demo: a persona record is NOT editable.
    //
    // This is a de-anonymisation guard, not a polish detail. An edit re-sends
    // `message.body`, and on a persona post the body is the PLAINTEXT (the ZK record
    // only ever exists on the wire, substituted in sendNormalMessage). Editing one
    // would therefore push the cleartext out as an ordinary message under the real
    // account — publishing exactly the link between author and post that the phantom
    // identity exists to hide. There is also nothing coherent to edit: the record is
    // already folded into every replica's Merkle roots, and the proof is over the
    // original body.
    message.persona == null &&
    message.personaEh == null &&
    (isMoreRecentThan(message.sent_at, DAY) || isMessageNoteToSelf(message)) &&
    Boolean(message.body)
  );
}

export function isWithinMaxEdits(
  message: ReadonlyMessageAttributesType
): boolean {
  return (
    isMessageNoteToSelf(message) ||
    (message.editHistory?.length ?? 0) <= MESSAGE_MAX_EDIT_COUNT
  );
}
