// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — SEALED-SENDER READINESS, and the warm-up that establishes it.
//
// A persona post only hides its author if it goes out SEALED. Sealed sender needs the
// recipient's profile key (the access key derives from it), and Desktop only learns a
// peer's profile key after a non-anonymous message has been exchanged in each
// direction. So on a fresh group the very first persona post has nobody to seal to.
//
// That is why PERSONAS_DEMO.md carried a manual step — "send a normal group message
// once so sessions with members exist before the first persona post" — which is exactly
// the kind of instruction people skip, and skipping it is not a visible failure. It is a
// silent de-anonymisation: the send either fails closed (best case) or goes out in a
// form that does not protect the author.
//
// This module removes the footgun. Before the first persona action we check every group
// member for a usable profile key; if any are missing we send ONE ordinary group message
// automatically, which is what teaches the peers our profile key and prompts theirs.
//
// Auto-sending is a deliberate trade. It puts a message in the chat the user did not
// type — so it is sent once per conversation, is clearly worded, and is never silent in
// the log. The alternative (blocking with a prompt) is more honest but strands a user
// who does not understand why their post was refused, and the whole point of this pass
// is that the protocol's requirements should not be the user's problem.
//
// NOTE this does not make sealed sender CERTAIN — the peer must also reply before we
// hold their key. `isSealedSenderReady` reports the honest current state, and the status
// panel surfaces it, rather than pretending a single outbound message is sufficient.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { isPersonasEngineEnabled } from './personasEngine.preload.ts';

const log = createLogger('personasSealedSender');

// The message we send to warm the group. Worded so a reader understands why it appeared
// rather than assuming the sender typed something odd.
const WARM_UP_BODY =
  '(setting up private posting for this group — you can ignore this message)';

// Conversations we have already warmed this process. Sending more than one warm-up is
// noise, and the second one teaches nobody anything new.
const warmedConversations = new Set<string>();

export type SealedSenderReadiness = {
  ready: boolean;
  /** Members we do not yet hold a profile key for — the ones blocking sealing. */
  missing: Array<string>;
  total: number;
};

/**
 * Which group members we can currently seal to.
 *
 * A member is "ready" when we hold their profile key, since that is what the access key
 * — and therefore unidentified (sealed) delivery — derives from. Members who have
 * explicitly disabled sealed sender can never be sealed to and are reported too, since
 * they cap what the group can achieve.
 */
export function getSealedSenderReadiness(
  conversation: ConversationModel
): SealedSenderReadiness {
  const members = conversation.getMembers();
  const ourId = window.ConversationController.getOurConversationId();

  const missing: Array<string> = [];
  let total = 0;

  for (const member of members) {
    if (member.id === ourId) {
      continue;
    }
    total += 1;
    if (!member.get('profileKey')) {
      // getTitle() rather than get('title'): the display title is derived from several
      // attributes (profile name, system contact, e164) and is not a stored field.
      missing.push(member.getTitle() || member.id);
    }
  }

  return { ready: missing.length === 0, missing, total };
}

export function isSealedSenderReady(conversation: ConversationModel): boolean {
  return getSealedSenderReadiness(conversation).ready;
}

/**
 * Make sure this group can be sealed to before a persona action runs.
 *
 * If any member is missing a profile key, sends ONE ordinary (attributable) group
 * message to establish the exchange, once per conversation per process. Returns the
 * readiness AFTER the attempt.
 *
 * The warm-up message is deliberately attributable — that is the entire point. It is an
 * ordinary message from the real account, which is what teaches peers the profile key
 * that later lets persona posts be sealed.
 */
export async function ensureSealedSenderWarmedUp(
  conversation: ConversationModel
): Promise<SealedSenderReadiness> {
  if (!isPersonasEngineEnabled()) {
    return getSealedSenderReadiness(conversation);
  }

  const before = getSealedSenderReadiness(conversation);
  if (before.ready) {
    return before;
  }

  if (warmedConversations.has(conversation.id)) {
    // Already warmed this session; the peers simply have not replied yet. Say so
    // rather than sending a second message that would teach them nothing.
    log.info(
      `ensureSealedSenderWarmedUp: already warmed ${conversation.idForLogging()}; still awaiting ${before.missing.length} peer(s)`
    );
    return before;
  }

  warmedConversations.add(conversation.id);
  log.info(
    `ensureSealedSenderWarmedUp: ${before.missing.length}/${before.total} member(s) lack a profile key ` +
      `(${before.missing.join(', ')}); sending one warm-up message`
  );

  try {
    // Visible on purpose: this one IS shown in the timeline. It is an ordinary message
    // the group can see, and hiding it would leave the user unable to explain a message
    // their account demonstrably sent.
    await conversation.enqueueMessageForSend({
      body: WARM_UP_BODY,
      attachments: [],
    });
  } catch (error) {
    log.error(
      `ensureSealedSenderWarmedUp: warm-up send failed: ${toLogFormat(error)}`
    );
    warmedConversations.delete(conversation.id);
  }

  return getSealedSenderReadiness(conversation);
}
