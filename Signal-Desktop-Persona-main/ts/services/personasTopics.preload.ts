// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — TOPIC CONTEXTS.
//
// A rate-limited persona is bound to a topic:
//
//     persona = H(sk || context || i),   i < MAX_PSEUDO
//
// so the same member has unlinkable petnames across topics, and at most MAX_PSEUDO
// identities within any one topic. The `context` is what makes that work, and every
// member of the group must agree on the same number for the same topic.
//
// The design calls for the CryptoPersonas server to draw that number at random, store
// it per thread, and hand it to clients. No such server exists in this architecture —
// the ZK engine runs client-side in each Desktop instance, and `deploy/` has only the
// Signal chat test-server and the storage-service. So the number is drawn CLIENT-side
// here and distributed over Signal itself:
//
//   1. the creator draws a cryptographically random context,
//   2. broadcasts a topic ANNOUNCEMENT to the group (`PZT2:` carriage, hidden from the
//      timeline like the other protocol traffic),
//   3. every member ingests it into this registry.
//
// Sending it over Signal rather than through the roster dir is deliberate: the roster
// dir is a local directory, so it only works when every instance is on one machine.
// Announcements ride the group, so the demo works across machines.
//
// A topic announcement is NOT a ZK record. It carries no proof and the engine never
// sees it — it is pure coordination metadata, the stand-in for the server's registry.
// Everything funnels through `resolveTopicContext`, so pointing this at a real server
// endpoint later is a one-function change.
//
// KNOWN LIMIT: a member who joins after a topic was announced will not have it, since
// there is no backfill. Re-announcing on join, or a server registry, would fix it.

import { randomBytes } from 'node:crypto';

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import {
  encodeTopicAnnouncement,
  type PersonaTopicAnnouncement,
} from './personasCarriage.std.ts';

const log = createLogger('personasTopics');

// Contexts are hashed inside the circuit as a field element. Stay well inside the
// exact-integer range of a JS number (2^53) so the value survives JSON and the napi
// boundary unchanged — a context that differs by one bit between members produces a
// different persona and silently breaks linkability within the topic.
const CONTEXT_BYTES = 6; // 48 bits

// name -> context, for this process. Rebuilt from announcements as they arrive.
const contextByTopic = new Map<string, number>();

export function drawRandomContext(): number {
  // Cryptographically random, not Math.random: the context should be unguessable, so
  // that knowing a topic's NAME does not let an outsider derive its personas.
  const bytes = randomBytes(CONTEXT_BYTES);
  let value = 0;
  for (const byte of bytes) {
    value = value * 256 + byte;
  }
  // Never 0 — that is the "no topic" sentinel used by the unlimited plain pseudonym.
  return value === 0 ? 1 : value;
}

/** Every topic this instance knows about, for the composer's picker. */
export function listTopics(): Array<{ name: string; context: number }> {
  return [...contextByTopic.entries()]
    .map(([name, context]) => ({ name, context }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/**
 * The context for a named topic, or undefined if this instance has not heard of it.
 * THE seam: a server-backed registry would replace only this function (and
 * `createTopic`), leaving every caller untouched.
 */
// The reverse of resolveTopicContext: the human name for a context number, if this
// instance has heard its announcement. Used when SENDING, to label a post with the
// context it was made under so recipients can show it even before their own registry has
// caught up.
export function nameForContext(context: number): string | undefined {
  return listTopics().find(topic => topic.context === context)?.name;
}

export function resolveTopicContext(name: string): number | undefined {
  return contextByTopic.get(name.trim());
}

/** Record a topic we learned about, from an announcement or from creating it. */
function rememberTopic(announcement: PersonaTopicAnnouncement): void {
  const name = announcement.name.trim();
  if (!name) {
    return;
  }
  const existing = contextByTopic.get(name);
  if (existing != null) {
    if (existing !== announcement.context) {
      // Two members created the same topic name concurrently. Deterministic tie-break
      // so every replica converges on one context rather than splitting the topic:
      // the numerically smaller context wins, everywhere, regardless of arrival order.
      const winner = Math.min(existing, announcement.context);
      log.warn(
        `rememberTopic: conflicting contexts for "${name}" (${existing} vs ${announcement.context}); keeping ${winner}`
      );
      contextByTopic.set(name, winner);
    }
    return;
  }
  contextByTopic.set(name, announcement.context);
  log.info(`rememberTopic: "${name}" -> context ${announcement.context}`);
  // Surface it to the composer's picker. The renderer cannot import this module
  // (preload), so redux is the bridge.
  window.reduxActions?.composer?.personaTopicLearned(name, announcement.context);
}

/** Receive seam: fold an announcement that arrived over Signal. */
export function ingestTopicAnnouncement(
  announcement: PersonaTopicAnnouncement
): void {
  rememberTopic(announcement);
}

/**
 * Create a topic: draw a random context, remember it, and announce it to the group so
 * every member uses the same number. Returns the context, or undefined on failure.
 *
 * Idempotent by name — creating an existing topic returns the known context and
 * re-announces it, which doubles as a crude backfill for members who missed it.
 */
export async function createTopic(
  conversation: ConversationModel,
  rawName: string
): Promise<number | undefined> {
  const name = rawName.trim();
  if (!name) {
    return undefined;
  }

  const context = contextByTopic.get(name) ?? drawRandomContext();
  rememberTopic({ name, context });

  try {
    await conversation.enqueueMessageForSend(
      {
        body: encodeTopicAnnouncement({ name, context }),
        attachments: [],
      },
      // Coordination traffic, not chatter — never show the raw carriage string.
      { hideFromTimeline: true }
    );
    log.info(`createTopic: announced "${name}" -> ${context}`);
    return context;
  } catch (error) {
    log.error(`createTopic: announce failed: ${toLogFormat(error)}`);
    // Keep it locally anyway; a re-announce can follow.
    return context;
  }
}
