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
import { drop } from '../util/drop.std.ts';
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
  requestedAt?: number;
};

// Per personas group: where its catch-up stands, and when we last asked.
type GroupCatchUp = {
  saved?: Saved;
  lastRequestSentAt: number;
};
const byGroup = new Map<string, GroupCatchUp>();

function catchUpOf(groupId: string): GroupCatchUp {
  let entry = byGroup.get(groupId);
  if (!entry) {
    entry = { lastRequestSentAt: 0 };
    byGroup.set(groupId, entry);
  }
  return entry;
}

registerPersistedExtra('catchUp', {
  snapshot: groupId => byGroup.get(groupId)?.saved ?? null,
  restore: (groupId, value) => {
    const v = value as Partial<Saved> | null;
    if (v && (v.state === 'done' || v.state === 'needed' || v.state === 'requested')) {
      catchUpOf(groupId).saved = {
        state: v.state,
        ...(typeof v.requestedAt === 'number' ? { requestedAt: v.requestedAt } : {}),
      };
    }
  },
});

/**
 * Called once a group's engine is built. `fresh`: no saved member state was restored, so
 * the replica is empty and needs the group's history. A member restored from an older
 * build (saved state, no catch-up entry) already has it.
 */
export function initPersonasCatchUp(groupId: string, { fresh }: { fresh: boolean }): void {
  const entry = catchUpOf(groupId);
  if (entry.saved) {
    return;
  }
  entry.saved = { state: fresh ? 'needed' : 'done' };
  // Saved straight away: the member state was just saved without it, and a restart
  // would otherwise read "has saved state" as "already caught up".
  personasExtrasChanged(groupId);
  log.info(`initPersonasCatchUp: ${entry.saved.state}`);
}

export function catchUpState(groupId: string | undefined): CatchUpState {
  return (groupId ? byGroup.get(groupId)?.saved?.state : undefined) ?? 'done';
}

/** Why persona actions are refused in a group for now, or undefined if they are not. */
export function catchUpBlockReason(groupId: string | undefined): string | undefined {
  if (catchUpState(groupId) === 'done') {
    return undefined;
  }
  return (
    'Waiting for a group admin to send you the group\u2019s state. Persona messages ' +
    'work once it arrives (the admin\u2019s app sends it automatically while it is open).'
  );
}

function markDone(groupId: string, how: string): void {
  const entry = catchUpOf(groupId);
  entry.saved = { state: 'done' };
  // Persist now: a fresh member has emitted nothing yet, so nothing else would save.
  const state = getPersonasEngine(groupId)?.exportMemberState();
  savePersonasState(groupId, state ? Buffer.from(state) : undefined);
  personasExtrasChanged(groupId);
  log.info(`catch-up done (${how})`);
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

async function sendRequest(groupId: string, conversation: ConversationModel): Promise<void> {
  const entry = catchUpOf(groupId);
  entry.lastRequestSentAt = Date.now();
  entry.saved = {
    state: 'requested',
    requestedAt: entry.saved?.requestedAt ?? entry.lastRequestSentAt,
  };
  personasExtrasChanged(groupId);
  try {
    await conversation.enqueueMessageForSend(
      { body: encodeCatchUpRequest(), attachments: [] },
      { hideFromTimeline: true }
    );
    log.info('catch-up requested from the group\u2019s admins');
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
  const groupId = conversation.get('groupId');
  if (catchUpState(groupId) === 'done') {
    return true;
  }
  if (!groupId || !getPersonasEngine(groupId)) {
    return false;
  }
  if (conversation.areWeAdmin() && otherAdmins(conversation).length === 0) {
    markDone(groupId, 'we are the only admin');
    return true;
  }
  if (Date.now() - catchUpOf(groupId).lastRequestSentAt >= REQUEST_EVERY_MS) {
    await sendRequest(groupId, conversation);
  }
  return false;
}

/** On every flag-loop tick: repeat unanswered requests, and the admin fallback. */
export async function maybeContinueCatchUp(): Promise<void> {
  for (const [groupId, entry] of [...byGroup]) {
    const conversation = window.ConversationController.get(groupId);
    if (!conversation) {
      continue;
    }
    // A new member asks as soon as it has an engine, not when a record first arrives.
    if (entry.saved?.state === 'needed') {
      // oxlint-disable-next-line no-await-in-loop
      await ensureCaughtUp(conversation);
      continue;
    }
    if (entry.saved?.state !== 'requested') {
      continue;
    }
    if (
      conversation.areWeAdmin() &&
      Date.now() - (entry.saved.requestedAt ?? Date.now()) >= ADMIN_FALLBACK_MS
    ) {
      markDone(groupId, 'no other admin answered; starting from our own state');
      continue;
    }
    if (Date.now() - entry.lastRequestSentAt >= REQUEST_EVERY_MS) {
      // oxlint-disable-next-line no-await-in-loop
      await sendRequest(groupId, conversation);
    }
  }
}

/**
 * Receive seam, before a persona record in `conversation` is ingested: a member that
 * still needs the history asks for it. The record does NOT wait for the copy.
 *
 * It used to, for up to 45 s, so that it could be shown. But this runs
 * inside the group's message queue, and the request itself is sent through that same
 * queue, so the request could not go out until the wait gave up: every new member
 * waited the full 45 s, then took the record in before the history and never showed
 * it. A record that arrives first is now held by the engine and shown once it applies
 * (`ingestRecordForTimeline`, `refreshPersonaFlags`).
 */
export function requestCatchUpIfNeeded(conversation: ConversationModel): void {
  const groupId = conversation.get('groupId');
  if (!groupId || catchUpState(groupId) !== 'needed') {
    return;
  }
  // Outside the queue we are running in, or the send would wait for us.
  setTimeout(() => {
    drop(ensureCaughtUp(conversation));
  }, 0);
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
  const groupId = conversation.get('groupId');
  const key = `${groupId}:${sender}`;
  const last = answeredAt.get(key) ?? 0;
  if (Date.now() - last < ANSWER_EVERY_MS) {
    return;
  }
  answeredAt.set(key, Date.now());

  const engine = getPersonasEngine(groupId);
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
    answeredAt.delete(key);
  }
}

// --- the newcomer side -----------------------------------------------------------------

type Copy = { parts: Array<string | undefined>; have: number; chars: number };
const copies = new Map<string, Copy>();

/** Receive seam: one part of a copy for group `wire.g`, 1:1 from `sender`. */
export function ingestCatchUpPart(
  wire: PersonaCatchUpPartWire,
  sender: string | undefined
): void {
  const groupId = wire.g;
  if (catchUpState(groupId) === 'done') {
    return;
  }
  const group = window.ConversationController.get(groupId);
  if (!isPersonasGroup(group)) {
    log.warn('ingestCatchUpPart: for a group that is not one of our personas groups; dropped');
    return;
  }
  if (!sender || !group || !group.isAdmin(sender as ServiceIdString)) {
    log.warn('ingestCatchUpPart: not from an admin of that group; dropped');
    return;
  }
  const key = `${groupId}:${sender}:${wire.s}`;
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

  const engine = getPersonasEngine(groupId);
  if (!engine) {
    return;
  }
  try {
    const added = engine.importCatchUp(Buffer.from(copy.parts.join(''), 'base64'));
    for (const other of [...copies.keys()]) {
      if (other.startsWith(`${groupId}:`)) {
        copies.delete(other);
      }
    }
    markDone(groupId, `${added} record(s) from an admin`);
  } catch (error) {
    log.error(`ingestCatchUpPart: the copy could not be taken in: ${toLogFormat(error)}`);
  }
}
