// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 6 — the ACTION layer: the single place the app turns a UI
// gesture into a CryptoPersonas record on the wire.
//
// Phases 3-5 wired one gesture (compose a post) and left the rest of the record
// surface — rate, poll, vote, scan — reachable only from the engine addon. Everything
// here follows the same three steps, in this order, because the order is what keeps
// the guarantees:
//
//   1. `ensurePersonaJoined` — never emit a member record before membership exists.
//      A persona action that runs un-joined either throws (post) or is rejected by
//      every replica's accept rule (rate/vote), and in the composer's case used to
//      silently degrade into an attributable plain message.
//   2. emit + self-ingest through personasEngine (a member's own replica must contain
//      its own records, or its roots diverge from everyone else's).
//   3. route correctly, following what the CIRCUIT already does. POSTS, POLLS,
//      BALLOTS and RATINGS all identify their author by a pseudonym in-circuit, so all
//      four ride the shared phantom — an attributable envelope would re-identify what
//      the proof anonymised. JOINS and SCANS stay attributable: the anti-Sybil
//      accounting rests on one membership per real account, which an anonymous join
//      would defeat. See personasCarriage for the marker split.
//
// Everything here is best-effort and logged: a failed action must never take down the
// message pipeline, and must never fall back to a weaker path.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { strictAssert } from '../util/assert.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  composePersonaPoll,
  composePersonaRate,
  composePersonaScan,
  composePersonaVote,
  isPersonasEngineEnabled,
  type PersonaPollDescriptor,
} from './personasEngine.preload.ts';
import { ensurePersonaJoined } from './personasMembership.preload.ts';
import { withPersonaProofLock } from './personasProofLock.preload.ts';

const log = createLogger('personasActions');

// Option 0 is the ban option, matching the engine's own e2e test
// (packages/personas-engine/test/converge.mjs) and the Rust replica test it mirrors.
// The engine decides settlement from the option INDEX, so the label order below is
// load-bearing: put "Keep" first and a majority to keep would revoke instead.
const BAN_OPTION_INDEX = 0;

const BAN_POLL_OPTIONS = ['Ban', 'Keep'] as const;

strictAssert(
  BAN_POLL_OPTIONS[BAN_OPTION_INDEX] === 'Ban',
  'personasActions: the ban option must sit at BAN_OPTION_INDEX'
);

// Rate a persona post by delta (+1 / -1). `targetEh` is the post's envelope hash,
// persisted on the message as `personaEh`.
export async function sendPersonaRate(
  conversation: ConversationModel,
  targetEh: string,
  delta: number
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  try {
    if (!(await ensurePersonaJoined(conversation))) {
      log.warn('sendPersonaRate: not joined; refusing to rate');
      return false;
    }
    const rate = await withPersonaProofLock('rating', () =>
      composePersonaRate(targetEh, delta)
    );
    if (!rate) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: rate.body, attachments: [] },
      // Protocol traffic, not chatter: send it, but never show the raw carriage
      // string in our own timeline or conversation list. (It rides the phantom —
      // see encodeRateBody — so the rater's account is hidden on the wire too.)
      { hideFromTimeline: true }
    );
    log.info(
      `sendPersonaRate: rated ${targetEh.slice(0, 12)}… by ${delta} (eh ${rate.eh.slice(0, 12)}…)`
    );
    return true;
  } catch (error) {
    log.error(`sendPersonaRate failed: ${toLogFormat(error)}`);
    return false;
  }
}

// Open a poll. For a ban poll, `targetEh` names the post under review and option
// BAN_OPTION_INDEX is the ban. The message we enqueue keeps the descriptor so our own
// timeline draws the bubble immediately; the wire body (personaCarriageBody) carries
// the record plus the same descriptor for recipients.
export async function sendPersonaPoll(
  conversation: ConversationModel,
  descriptor: PersonaPollDescriptor,
  targetEh?: string
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  try {
    if (!(await ensurePersonaJoined(conversation))) {
      log.warn('sendPersonaPoll: not joined; refusing to open a poll');
      return false;
    }
    const poll = await withPersonaProofLock('poll', () =>
      composePersonaPoll(descriptor, targetEh)
    );
    if (!poll) {
      return false;
    }
    await conversation.enqueueMessageForSend({
      // No plaintext of its own — the poll bubble renders from personaPoll.
      body: undefined,
      attachments: [],
      personaEh: poll.eh,
      // The poll rides the phantom, so its creator is unlinkable — including from
      // our own point of view. Label our copy Anonymous too, so the sender's screen
      // matches what every recipient sees.
      personaAnonymous: true,
      personaPoll: {
        question: descriptor.question,
        options: [...descriptor.options],
        kind: descriptor.kind,
        target: descriptor.kind === 'ban' ? targetEh : undefined,
      },
      personaCarriageBody: poll.body,
    });
    log.info(
      `sendPersonaPoll: opened ${descriptor.kind} poll (eh ${poll.eh.slice(0, 12)}…)`
    );
    return true;
  } catch (error) {
    log.error(`sendPersonaPoll failed: ${toLogFormat(error)}`);
    return false;
  }
}

// Open a ban poll on a specific post. The question names the persona rather than the
// account, because the persona is the only thing anyone is entitled to know.
export async function sendPersonaBanPoll(
  conversation: ConversationModel,
  targetEh: string,
  persona: string | undefined
): Promise<boolean> {
  const subject = persona ? `~${persona}` : 'this anonymous author';
  return sendPersonaPoll(
    conversation,
    {
      question: `Revoke ${subject}?`,
      options: [...BAN_POLL_OPTIONS],
      kind: 'ban',
    },
    targetEh
  );
}

// Cast a ballot. `pollEh` is the poll message's `personaEh`.
export async function sendPersonaVote(
  conversation: ConversationModel,
  pollEh: string,
  optionIndex: number
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  try {
    if (!(await ensurePersonaJoined(conversation))) {
      log.warn('sendPersonaVote: not joined; refusing to vote');
      return false;
    }
    const vote = await withPersonaProofLock('vote', () =>
      composePersonaVote(pollEh, optionIndex)
    );
    if (!vote) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: vote.body, attachments: [] },
      { hideFromTimeline: true }
    );
    log.info(
      `sendPersonaVote: voted option ${optionIndex} in ${pollEh.slice(0, 12)}… (eh ${vote.eh.slice(0, 12)}…)`
    );
    return true;
  } catch (error) {
    log.error(`sendPersonaVote failed: ${toLogFormat(error)}`);
    return false;
  }
}

// If `messageId` is a persona poll, cast the ballot through the engine and report
// true (the caller then skips Signal's own poll-vote send). A ZK ballot is
// single-choice, so only the first selected index is used.
//
// We also stash the chosen index on the message as `personaMyVote`. That is purely
// local bookkeeping for our own UI: a ballot is anonymous by construction, so the
// engine will never tell us — or anyone — which option was ours.
export async function maybeSendPersonaVote({
  messageId,
  optionIndexes,
}: {
  messageId: string;
  optionIndexes: ReadonlyArray<number>;
}): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }

  const message = window.MessageCache.getById(messageId);
  const pollEh = message?.get('personaEh');
  if (!message || !pollEh || message.get('personaPoll') == null) {
    return false;
  }

  const optionIndex = optionIndexes[0];
  if (optionIndex == null) {
    return false;
  }

  const conversation = window.ConversationController.get(
    message.get('conversationId')
  );
  if (!conversation) {
    return false;
  }

  const sent = await sendPersonaVote(conversation, pollEh, optionIndex);
  if (sent) {
    message.set({ personaMyVote: optionIndex });
    await window.MessageCache.saveMessage(message.attributes);
  }
  return true;
}

// ---------------------------------------------------------------------------
// Rating on Signal's own reaction gesture.
// ---------------------------------------------------------------------------

// The two emoji that mean "rate", and the delta each carries. Matched on the leading
// codepoint so every skin-tone variant (👍🏽, 👎🏿, …) counts the same — the rating is
// about the sentiment, not the modifier.
const THUMBS_UP = '\u{1F44D}';
const THUMBS_DOWN = '\u{1F44E}';

function rateDeltaForEmoji(emoji: string): number | undefined {
  if (emoji.startsWith(THUMBS_UP)) {
    return 1;
  }
  if (emoji.startsWith(THUMBS_DOWN)) {
    return -1;
  }
  return undefined;
}

// If this reaction is a thumbs on a persona post, emit it as a RATE record and report
// true (the caller then skips the ordinary Signal reaction). Anything else returns
// false and falls through untouched.
//
// `remove` inverts the delta: un-thumbs-upping is a -1, which is the closest the
// engine's append-only rating model gets to a retraction. Ratings accumulate, so this
// nets back to zero rather than deleting the original ballot — appropriate for a
// system whose whole point is that history is not rewritten.
export async function maybeSendPersonaRateForReaction({
  messageId,
  emoji,
  remove,
}: {
  messageId: string;
  emoji: string;
  remove: boolean;
}): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }

  const delta = rateDeltaForEmoji(emoji);
  if (delta == null) {
    return false;
  }

  const message = window.MessageCache.getById(messageId);
  const targetEh = message?.get('personaEh');
  if (!message || !targetEh || message.get('personaPoll') != null) {
    // Not a persona post (a poll is not rateable), so not ours to handle.
    return false;
  }

  const conversation = window.ConversationController.get(
    message.get('conversationId')
  );
  if (!conversation) {
    return false;
  }

  const applied = delta * (remove ? -1 : 1);
  log.info(
    `maybeSendPersonaRateForReaction: routing ${emoji} to a rate of ${applied}`
  );
  await sendPersonaRate(conversation, targetEh, applied);
  return true;
}

// Emit a scan, absorbing the revocation callbacks fired since our last one. This is
// what turns a settled ban into a flag on everyone's replica, so it runs on a timer
// (see startPersonaScanLoop) rather than waiting for a human.
// A scan is a SYNCHRONOUS Groth16 proof (`emitScan()` is a blocking napi call) executed
// in the render process, where the preload context lives. It is the most expensive thing
// this integration does: it holds the proving key set resident and blocks the main thread
// for its duration.
//
// The 30 s timer could never overlap with itself in practice, so this went unguarded.
// Then the "Scan now" menu item made overlap trivially reachable — a demo-nervous double
// click queues a second proof behind the first, and each one costs the full working set.
// Enough of them and the render process is SIGKILLed (exit code 9) rather than throwing
// anything catchable.
//
// So: one scan at a time, globally. A scan absorbs whatever is outstanding AT THE MOMENT
// IT RUNS, which means a request arriving while one is in flight would have been
// redundant anyway — dropping it loses nothing.
let scanInFlight = false;

export async function sendPersonaScan(
  conversation: ConversationModel
): Promise<boolean> {
  if (!isPersonasEngineEnabled()) {
    return false;
  }
  if (scanInFlight) {
    log.info('sendPersonaScan: a scan is already in flight; skipping');
    return false;
  }
  scanInFlight = true;
  try {
    // A scan is only meaningful once we are a member, but unlike the others it should
    // not CAUSE a join — a lurking instance that never posted has nothing to absorb.
    const scan = await withPersonaProofLock('scan', composePersonaScan);
    if (!scan) {
      return false;
    }
    await conversation.enqueueMessageForSend(
      { body: scan.body, attachments: [] },
      { hideFromTimeline: true }
    );
    log.info(`sendPersonaScan: scan sent (eh ${scan.eh.slice(0, 12)}…)`);
    return true;
  } catch (error) {
    log.error(`sendPersonaScan failed: ${toLogFormat(error)}`);
    return false;
  } finally {
    // `finally`, not a flag reset on each path: if this is ever left true the scan loop
    // stops silently and bans quietly never settle again — the worst failure mode this
    // integration has, because everything still LOOKS fine.
    scanInFlight = false;
  }
}
