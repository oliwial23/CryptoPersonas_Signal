// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: an out-of-band contact roster so demo instances running on one
// machine can discover each other WITHOUT CDSI. libsignal-net's localTestServer
// mode DISCARDs the CDSI port (see preconnect.preload.ts), so Signal's normal
// "find by phone number" flow — which resolves E.164 -> ACI through CDSI — is
// unavailable. Instead, each instance publishes its own identity
// {aci, pni, e164, profileKey} to a shared directory on boot and seeds every
// *other* entry as a local private conversation, carrying the peer's profileKey
// so sealed sender works (the access key derives from it). This is the same
// discovery mechanism the group fan-out will reuse in Phase 3.
//
// Gated on PERSONAS_AUTO_REGISTER / PERSONAS_ROSTER_DIR so normal builds are
// unaffected. The directory is re-polled so instances find each other regardless
// of launch order (and so late joiners appear); every step is idempotent.

import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { createLogger } from '../logging/log.std.ts';
import { itemStorage } from './Storage.preload.ts';
import { ourProfileKeyService } from '../services/ourProfileKey.std.ts';
import { DataWriter } from '../sql/Client.preload.ts';
import * as Bytes from '../Bytes.std.ts';
import { drop } from '../util/drop.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { isPniString } from '../types/ServiceId.std.ts';

const log = createLogger('personaRoster');

const DEFAULT_ROSTER_DIR = join(tmpdir(), 'personas-demo-roster');
const POLL_INTERVAL_MS = 5000;

type RosterEntry = {
  aci: string;
  pni?: string;
  e164: string;
  profileKey?: string; // base64
};

// Active only for demo instances (those that auto-register), keyed off the same
// signal as personaAutoRegister, or when a directory is set explicitly.
export function getRosterDir(): string | undefined {
  if (!process.env.PERSONAS_AUTO_REGISTER && !process.env.PERSONAS_ROSTER_DIR) {
    return undefined;
  }
  return process.env.PERSONAS_ROSTER_DIR?.trim() || DEFAULT_ROSTER_DIR;
}

// Peers we have already turned into local conversations this session.
const seededAcis = new Set<string>();
let hasAutoOpened = false;

async function writeMyRosterEntry(dir: string): Promise<void> {
  const aci = itemStorage.user.getAci();
  const e164 = itemStorage.user.getNumber();
  if (!aci || !e164) {
    log.warn('writeMyRosterEntry: not registered yet; skipping');
    return;
  }

  const pni = itemStorage.user.getPni();
  const profileKeyBytes = await ourProfileKeyService.get();
  const entry: RosterEntry = {
    aci,
    pni: pni ?? undefined,
    e164,
    profileKey: profileKeyBytes ? Bytes.toBase64(profileKeyBytes) : undefined,
  };

  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${e164.replace(/[^0-9+]/g, '')}.json`);
  writeFileSync(file, JSON.stringify(entry, null, 2), 'utf8');
  log.info(`writeMyRosterEntry: published ${file}`);
}

async function seedPeersFromRoster(dir: string): Promise<void> {
  const myAci = itemStorage.user.getAci();

  let files: Array<string>;
  try {
    files = readdirSync(dir).filter(name => name.endsWith('.json'));
  } catch {
    // Directory may not exist yet (no peer, including us, has published).
    return;
  }

  for (const name of files) {
    let entry: RosterEntry | undefined;
    try {
      entry = JSON.parse(readFileSync(join(dir, name), 'utf8')) as RosterEntry;
    } catch (error) {
      log.warn(`seedPeersFromRoster: bad entry ${name}: ${toLogFormat(error)}`);
      continue;
    }

    if (!entry?.aci || entry.aci === myAci || seededAcis.has(entry.aci)) {
      continue;
    }
    seededAcis.add(entry.aci);

    const conversation = window.ConversationController.getOrCreate(
      entry.aci,
      'private',
      {
        e164: entry.e164,
        pni: isPniString(entry.pni) ? entry.pni : undefined,
      }
    );

    if (entry.profileKey) {
      // eslint-disable-next-line no-await-in-loop
      await conversation.setProfileKey(entry.profileKey, {
        reason: 'personaRoster',
      });
    }

    // Mark the peer as a trusted, profile-shared contact so it passes the
    // group-composer filter (isTrusted needs profileSharing / a system contact /
    // a shared group) and shows up in "New group". All roster peers are trusted
    // demo members by construction.
    conversation.set({ profileSharing: true });

    // Surface it in the conversation list and warm identity/prekeys/profile so
    // the first send can go out sealed without a CDSI round trip.
    conversation.set({ active_at: Date.now() });
    drop(DataWriter.updateConversation(conversation.attributes));
    drop(conversation.getProfiles());
    log.info(`seedPeersFromRoster: seeded ${entry.e164} (${entry.aci})`);

    if (!hasAutoOpened) {
      hasAutoOpened = true;
      window.reduxActions.conversations.showConversation({
        conversationId: conversation.id,
      });
    }
  }
}

// Publish our identity and begin seeding peers, re-polling so any launch order
// converges. Non-blocking; safe to call once the account is registered and the
// ConversationController has completed its initial fetch.
export function startPersonaRosterSync(): void {
  const dir = getRosterDir();
  if (!dir) {
    return;
  }

  log.info(`startPersonaRosterSync: using roster dir ${dir}`);
  drop(writeMyRosterEntry(dir));
  drop(seedPeersFromRoster(dir));
  setInterval(() => drop(seedPeersFromRoster(dir)), POLL_INTERVAL_MS);
}
