// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — LATE-JOIN CATCH-UP.
//
// Every persona post proves membership of the group's object tree at some root, and a
// member accepts it only if it built that root itself. The tree is built from every
// record since the group began. A member added later has none of them: its posts name
// roots nobody else has, and it cannot apply anyone else's. Persona messages then fail
// in both directions while ordinary messages work.
//
// So a NEW member (no saved state) asks the group, and a group admin's app answers on
// its own with the admin's history: every record, each at its barrier and under its
// real envelope hash, with the text of past posts and polls removed — the newcomer
// needs the group's state, not its old messages (Engine.exportCatchUp). It arrives in
// parts, 1:1, under the admin's own account.
//
// TRUST. The newcomer takes the admin's copy as it is. Records are verified as usual,
// but nothing checks the copy is complete, and a dishonest admin could hand over a
// doctored one: the newcomer's persona posts would then be refused by everyone else
// (they name a tree only it has), and the admin would recognise them. Existing members
// are never affected — they keep checking every post against their own state.
//
// Until the copy is in, persona actions are refused (a post built on the empty tree
// would be stranded for good, and so would the member), and received persona records
// wait a little for it so they can still be shown.

import { randomBytes } from 'node:crypto';

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { itemStorage } from '../textsecure/Storage.preload.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { sleep } from '../util/sleep.std.ts';
import type { ServiceIdString } from '../types/ServiceId.std.ts';
import {
  encodeCatchUpParts,
  encodeCatchUpRequest,
  type PersonaCatchUpPartWire,
} from './personasCarriage.std.ts';
import { getPersonasEngine } from './personasEngine.preload.ts';
import { isPersonasGroup } from './personasPhantom.preload.ts';
import {
  personasExtrasChanged,
  registerPersistedExtra,
  savePersonasState,
} from './personasPersistence.preload.ts';

const log = createLogger('personasCatchUp');

// How often a request is repeated while no copy has come.
const REQUEST_EVERY_MS = 60_000;
// How long a received persona record waits for the copy (once per request).
const HOLD_RECORDS_MS = 45_000;
// An admin with no other admin to ask, or whom no other admin answers in this time,
// starts from its own state: in a new group, admins are the founders.
const ADMIN_FALLBACK_MS = 60_000;
// Answer the same member at most this often.
const ANSWER_EVERY_MS = 20_000;
// The most a copy being assembled may hold.
const MAX_COPY_CHARS = 32 * 1024 * 1024;

export type CatchUpState = 'done' | 'needed' | 'requested';

type Saved = {
  state: CatchUpState;
  conversationId?: string;
  requestedAt?: number;
};

let saved: Saved | undefined;
let lastRequestSentAt = 0;
// Settled once the copy is in; records waiting for it race it against their deadline.
let arrived: Promise<void> | undefined;
let signalArrived: (() => void) | undefined;
function copyArrived(): Promise<void> {
  arrived ??= new Promise<void>(resolve => {
    signalArrived = resolve;
  });
  return arrived;
}

registerPersistedExtra('catchUp', {
  snapshot: () => saved ?? null,
  restore: value => {
    const v = value as Partial<Saved> | null;
    if (v && (v.state === 'done' || v.state === 'needed' || v.state === 'requested')) {
      saved = {
        state: v.state,
        ...(typeof v.conversationId === 'string' ? { conversationId: v.conversationId } : {}),
        ...(typeof v.requestedAt === 'number' ? { requestedAt: v.requestedAt } : {}),
      };
    }
  },
});

/**
 * Called once the engine is built. `fresh`: no saved member state was restored, so this
 * replica is empty and needs the group's history. A member restored from an older build
 * (saved state, no catch-up entry) already has it.
 */
export function initPersonasCatchUp({ fresh }: { fresh: boolean }): void {
  if (saved) {
    return;
  }
  saved = { state: fresh ? 'needed' : 'done' };
  // Saved straight away: the member state was just saved without it, and a restart
  // would otherwise read "has saved state" as "already caught up".
  personasExtrasChanged();
  log.info(`initPersonasCatchUp: ${saved.state}`);
}

export function catchUpState(): CatchUpState {
  return saved?.state ?? 'done';
}

/** Why persona actions are refused for now, or undefined if they are not. */
export function catchUpBlockReason(): string | undefined {
  if (catchUpState() === 'done') {
    return undefined;
  }
  return (
    'Waiting for a group admin to send you the group’s state. Persona messages ' +
    'work once it arrives (the admin’s app sends it automatically while it is open).'
  );
}

function markDone(how: string): void {
  saved = { state: 'done' };
  // Persist now: a fresh member has emitted nothing yet, so nothing else would save.
  const state = getPersonasEngine()?.exportMemberState();
  savePersonasState(state ? Buffer.from(state) : undefined);
  personasExtrasChanged();
  log.info(`catch-up done (${how})`);
  signalArrived?.();
}

const ourAci = (): string | undefined => itemStorage.user.getAci();

function otherAdmins(conversation: ConversationModel): Array<string> {
  const us = ourAci();
  return conversation
    .getMembers()
    .map(member => member.getServiceId())
    .filter(
      (id): id is ServiceIdString =>
        id != null && id !== us && conversation.isAdmin(id)
    );
}

async function sendRequest(conversation: ConversationModel): Promise<void> {
  lastRequestSentAt = Date.now();
  saved = {
    state: 'requested',
    conversationId: conversation.id,
    requestedAt: saved?.requestedAt ?? lastRequestSentAt,
  };
  personasExtrasChanged();
  try {
    await conversation.enqueueMessageForSend(
      { body: encodeCatchUpRequest(), attachments: [] },
      { hideFromTimeline: true }
    );
    log.info('catch-up requested from the group’s admins');
  } catch (error) {
    log.error(`catch-up request failed to send: ${toLogFormat(error)}`);
  }
}

/**
 * True once this member has the group's state. Otherwise asks for it (an admin with no
 * other admin to ask simply starts from its own) and returns false: persona actions must
 * wait.
 */
export async function ensureCaughtUp(conversation: ConversationModel): Promise<boolean> {
  if (catchUpState() === 'done') {
    return true;
  }
  if (!getPersonasEngine()) {
    return false;
  }
  if (conversation.areWeAdmin() && otherAdmins(conversation).length === 0) {
    markDone('we are the only admin');
    return true;
  }
  if (Date.now() - lastRequestSentAt >= REQUEST_EVERY_MS) {
    await sendRequest(conversation);
  }
  return false;
}

/** On every flag-loop tick: repeat an unanswered request, and the admin fallback. */
export async function maybeContinueCatchUp(): Promise<void> {
  if (saved?.state !== 'requested' || !saved.conversationId) {
    return;
  }
  const conversation = window.ConversationController.get(saved.conversationId);
  if (!conversation) {
    return;
  }
  if (
    conversation.areWeAdmin() &&
    Date.now() - (saved.requestedAt ?? Date.now()) >= ADMIN_FALLBACK_MS
  ) {
    markDone('no other admin answered; starting from our own state');
    return;
  }
  if (Date.now() - lastRequestSentAt >= REQUEST_EVERY_MS) {
    await sendRequest(conversation);
  }
}

/**
 * Receive seam, before a persona record in `conversation` is ingested. A member that
 * still needs the history asks for it, and the record waits (a bounded while) for the
 * copy, so that it can be shown: one that arrives before the history cannot be applied
 * yet, and is only applied — not shown — when the copy lands.
 */
export async function holdRecordForCatchUp(conversation: ConversationModel): Promise<void> {
  if (catchUpState() === 'done') {
    return;
  }
  if (catchUpState() === 'needed') {
    await ensureCaughtUp(conversation);
  }
  const deadline = (saved?.requestedAt ?? Date.now()) + HOLD_RECORDS_MS;
  const wait = deadline - Date.now();
  if (catchUpState() === 'done' || wait <= 0) {
    return;
  }
  // Whichever comes first: the copy, or the deadline.
  const abort = new AbortController();
  await Promise.race([copyArrived(), sleep(wait, abort.signal).catch(() => undefined)]);
  abort.abort();
}

// --- the admin side --------------------------------------------------------------------

const answeredAt = new Map<string, number>();

/** Receive seam: a catch-up request in group `conversation` from `sender`. */
export async function answerCatchUpRequest(
  conversation: ConversationModel,
  sender: string | undefined
): Promise<void> {
  if (!sender || sender === ourAci() || !conversation.areWeAdmin()) {
    return;
  }
  // Only from a member of this group, and only once our own copy is complete.
  if (!conversation.getMembers().some(member => member.getServiceId() === sender)) {
    log.warn('answerCatchUpRequest: the requester is not a member of this group');
    return;
  }
  // A new admin settles its own state first: the only admin starts from its own, and
  // one with fellow admins asks them (falling back to its own after a while).
  if (!(await ensureCaughtUp(conversation))) {
    log.info('answerCatchUpRequest: our own state is not complete yet; not answering');
    return;
  }
  const last = answeredAt.get(sender) ?? 0;
  if (Date.now() - last < ANSWER_EVERY_MS) {
    return;
  }
  answeredAt.set(sender, Date.now());

  const engine = getPersonasEngine();
  const groupId = conversation.get('groupId');
  const recipient = window.ConversationController.get(sender);
  if (!engine || !groupId || !recipient) {
    return;
  }
  const parts = encodeCatchUpParts(
    groupId,
    randomBytes(8).toString('hex'),
    new Uint8Array(engine.exportCatchUp())
  );
  log.info(`answerCatchUpRequest: sending the group state in ${parts.length} part(s)`);
  try {
    // In order and one at a time, so a failure stops the copy rather than leaving holes.
    for (const body of parts) {
      // oxlint-disable-next-line no-await-in-loop
      await recipient.enqueueMessageForSend(
        { body, attachments: [] },
        { hideFromTimeline: true }
      );
    }
  } catch (error) {
    log.error(`answerCatchUpRequest: sending failed: ${toLogFormat(error)}`);
    answeredAt.delete(sender);
  }
}

// --- the newcomer side -----------------------------------------------------------------

type Copy = { parts: Array<string | undefined>; have: number; chars: number };
const copies = new Map<string, Copy>();

/** Receive seam: one part of a copy, 1:1 from `sender`. */
export function ingestCatchUpPart(
  wire: PersonaCatchUpPartWire,
  sender: string | undefined
): void {
  if (catchUpState() === 'done') {
    return;
  }
  const group = window.ConversationController.get(wire.g);
  if (!isPersonasGroup(group)) {
    log.warn('ingestCatchUpPart: for a group that is not our personas group; dropped');
    return;
  }
  if (!sender || !group || !group.isAdmin(sender as ServiceIdString)) {
    log.warn('ingestCatchUpPart: not from an admin of that group; dropped');
    return;
  }
  const key = `${sender}:${wire.s}`;
  let copy = copies.get(key);
  if (!copy) {
    copy = { parts: new Array<string | undefined>(wire.n), have: 0, chars: 0 };
    copies.set(key, copy);
  }
  if (copy.parts.length !== wire.n || copy.parts[wire.i] != null) {
    return;
  }
  copy.chars += wire.d.length;
  if (copy.chars > MAX_COPY_CHARS) {
    log.warn('ingestCatchUpPart: copy too large; dropped');
    copies.delete(key);
    return;
  }
  copy.parts[wire.i] = wire.d;
  copy.have += 1;
  if (copy.have < wire.n) {
    return;
  }
  copies.delete(key);

  const engine = getPersonasEngine();
  if (!engine) {
    return;
  }
  try {
    const added = engine.importCatchUp(Buffer.from(copy.parts.join(''), 'base64'));
    copies.clear();
    markDone(`${added} record(s) from an admin`);
  } catch (error) {
    log.error(`ingestCatchUpPart: the copy could not be taken in: ${toLogFormat(error)}`);
  }
}
