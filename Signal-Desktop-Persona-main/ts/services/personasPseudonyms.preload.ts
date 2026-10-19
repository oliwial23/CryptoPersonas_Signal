// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo — the PSEUDONYM LOG for unlimited personas.
//
// The plain (non-rate-limited) pseudonym takes no topic and a member may mint as many
// as they like: `persona = H(sk, nonce)` for any nonce they choose. Until now the
// composer drew a FRESH random nonce on every send, which meant a member could never
// post twice under the same identity — every message was a new stranger. That makes
// the unlimited persona useless for the thing pseudonyms are actually for: building a
// reputation, or holding a conversation, without revealing who you are.
//
// So nonces are now remembered. This is the Desktop equivalent of the CLI's
// `gen-pseudo` + `pseudo-index` pair: mint one, then choose it again later.
//
// The PETNAME is learned rather than computed. The engine derives it internally
// (`petname(claimed)` over `H(sk, nonce)`) and only hands it back on the `Emitted`
// from an `emit*` call — there is no "what would this nonce be called?" query on the
// addon. So a freshly minted pseudonym shows as unused until its first post, after
// which we record the name the engine gave it.
//
// In memory only, like the topic registry: the demo backend is ephemeral and the
// engine's Member is rebuilt each process, so a nonce from a previous run would derive
// a different persona anyway (the secret key is new).

import { randomBytes } from 'node:crypto';

import { createLogger } from '../logging/log.std.ts';
import {
  personasExtrasChanged,
  registerPersistedExtra,
} from './personasPersistence.preload.ts';

const log = createLogger('personasPseudonyms');

// Matches the topic-context width: comfortably inside JS's exact-integer range so the
// value survives JSON and the napi boundary unchanged.
const NONCE_BYTES = 6; // 48 bits

export type PersonaPseudonym = {
  /** The nonce that derives this persona. Stable — this is the identity. */
  nonce: number;
  /** The engine's petname, once a post under this nonce has revealed it. */
  petname?: string;
  /** Creation order, for a stable label before the petname is known. */
  index: number;
};

// Per personas group: a member's pseudonyms in one group are its own there, derived from
// that group's member key, and unlinkable to any other group's.
const byGroup = new Map<string, Array<PersonaPseudonym>>();

function pseudonymsOf(groupId: string): Array<PersonaPseudonym> {
  let list = byGroup.get(groupId);
  if (!list) {
    list = [];
    byGroup.set(groupId, list);
  }
  return list;
}

// Saved with the member state (personasPersistence), so a restart keeps every
// pseudonym: the nonce is the identity, and losing it means never posting as it again.
registerPersistedExtra('pseudonyms', {
  snapshot: groupId => pseudonymsOf(groupId).map(p => ({ ...p })),
  restore: (groupId, value) => {
    if (!Array.isArray(value)) {
      return;
    }
    const restored = value.filter(
      (p): p is PersonaPseudonym =>
        typeof p?.nonce === 'number' &&
        Number.isSafeInteger(p.nonce) &&
        typeof p?.index === 'number' &&
        (p.petname === undefined || typeof p.petname === 'string')
    );
    const pseudonyms = pseudonymsOf(groupId);
    pseudonyms.splice(0, pseudonyms.length, ...restored);
    notify(groupId);
  },
});

function drawNonce(): number {
  // Cryptographically random rather than sequential: a guessable nonce would let an
  // observer derive the persona for a member whose secret key they later learn, and
  // sequential values would leak how many personas someone has minted.
  const bytes = randomBytes(NONCE_BYTES);
  let value = 0;
  for (const byte of bytes) {
    value = value * 256 + byte;
  }
  return value === 0 ? 1 : value;
}

export function listPseudonyms(groupId: string): ReadonlyArray<PersonaPseudonym> {
  return pseudonymsOf(groupId);
}

/** Mint a new unlimited pseudonym in a group. Its petname appears after its first post. */
export function createPseudonym(groupId: string): PersonaPseudonym {
  const pseudonyms = pseudonymsOf(groupId);
  const entry: PersonaPseudonym = {
    nonce: drawNonce(),
    index: pseudonyms.length + 1,
  };
  pseudonyms.push(entry);
  log.info(`createPseudonym: minted #${entry.index}`);
  notify(groupId);
  personasExtrasChanged(groupId);
  return entry;
}

/**
 * Record the petname the engine assigned to a nonce, learned from a post's `Emitted`.
 * Idempotent — the same nonce always derives the same persona, so a second sighting
 * should agree, and a disagreement means the engine's key changed underneath us.
 */
export function recordPetname(groupId: string, nonce: number, petname: string): void {
  const entry = pseudonymsOf(groupId).find(p => p.nonce === nonce);
  if (!entry || entry.petname === petname) {
    return;
  }
  if (entry.petname != null) {
    log.warn(
      `recordPetname: nonce ${nonce} was ~${entry.petname}, now ~${petname} — the engine's key likely changed`
    );
  }
  entry.petname = petname;
  notify(groupId);
  personasExtrasChanged(groupId);
}

/** Forget a group's pseudonyms — after a reset, the new secret key derives different ones. */
export function clearPseudonyms(groupId: string): void {
  pseudonymsOf(groupId).splice(0);
  notify(groupId);
  personasExtrasChanged(groupId);
}

/** Ensure a group has at least one pseudonym, so the picker is never empty. */
export function ensureOnePseudonym(groupId: string): PersonaPseudonym {
  return pseudonymsOf(groupId)[0] ?? createPseudonym(groupId);
}

function notify(groupId: string): void {
  // The composer is a renderer component and cannot import this module, so redux is
  // the bridge — same arrangement as the topic registry.
  window.reduxActions?.composer?.personaPseudonymsChanged(
    groupId,
    pseudonymsOf(groupId).map(p => ({ ...p }))
  );
}
