// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: an out-of-band contact roster so demo instances can discover each
// other WITHOUT CDSI. libsignal-net's localTestServer
// mode DISCARDs the CDSI port (see preconnect.preload.ts), so Signal's normal
// "find by phone number" flow — which resolves E.164 -> ACI through CDSI — is
// unavailable. Instead, each instance publishes its own identity
// {aci, pni, e164, profileKey} to a shared directory on boot and seeds every
// *other* entry as a local private conversation, carrying the peer's profileKey
// so sealed sender works (the access key derives from it). This is the same
// discovery mechanism the group fan-out will reuse in Phase 3.
//
// Two backends for the same entries:
//   DIRECTORY (default)  the member directory on our server (deploy/play/directory.js),
//                        reached through the same localhost relay as the chat server.
//                        Works across machines, so it is what installed clients use.
//   FOLDER               a shared local directory, when PERSONAS_ROSTER_DIR is set
//                        explicitly — the original one-machine mechanism, kept for
//                        laptop runs against a local backend (personas-run.sh sets it).
//
// Gated on PERSONAS_AUTO_REGISTER / PERSONAS_ROSTER_DIR so normal builds are
// unaffected. The directory is re-polled so instances find each other regardless
// of launch order (and so late joiners appear); every step is idempotent.

import { readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { request } from 'node:https';
import { randomBytes } from 'node:crypto';

import { createLogger } from '../logging/log.std.ts';
import { itemStorage } from './Storage.preload.ts';
import { ourProfileKeyService } from '../services/ourProfileKey.std.ts';
import { DataWriter } from '../sql/Client.preload.ts';
import * as Bytes from '../Bytes.std.ts';
import { drop } from '../util/drop.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { isAciString } from '../util/isAciString.std.ts';
import { isPniString } from '../types/ServiceId.std.ts';

const log = createLogger('personaRoster');

const DEFAULT_ROSTER_DIR = join(tmpdir(), 'personas-demo-roster');
const POLL_INTERVAL_MS = 5000;
// Re-publish our own entry this often, so a restarted directory relearns us.
const REPUBLISH_INTERVAL_MS = 5 * 60_000;
const DIRECTORY_PATH = '/personas/directory';
const DIRECTORY_TIMEOUT_MS = 10_000;

type RosterEntry = {
  aci: string;
  pni?: string;
  e164: string;
  // Display name (directory only). The folder entries predate it.
  name?: string;
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

async function myEntry(): Promise<RosterEntry | undefined> {
  const aci = itemStorage.user.getAci();
  const e164 = itemStorage.user.getNumber();
  if (!aci || !e164) {
    log.warn('myEntry: not registered yet');
    return undefined;
  }
  const pni = itemStorage.user.getPni();
  const profileKeyBytes = await ourProfileKeyService.get();
  return {
    aci,
    pni: pni ?? undefined,
    e164,
    name: process.env.NODE_APP_INSTANCE?.trim() || e164,
    profileKey: profileKeyBytes ? Bytes.toBase64(profileKeyBytes) : undefined,
  };
}

// --- folder backend -----------------------------------------------------------------

async function writeMyRosterEntry(dir: string): Promise<void> {
  const entry = await myEntry();
  if (!entry) {
    return;
  }
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${entry.e164.replace(/[^0-9+]/g, '')}.json`);
  writeFileSync(file, JSON.stringify(entry, null, 2), 'utf8');
  log.info(`writeMyRosterEntry: published ${file}`);
}

function readFolderEntries(dir: string): Array<RosterEntry> {
  let files: Array<string>;
  try {
    files = readdirSync(dir).filter(name => name.endsWith('.json'));
  } catch {
    // Directory may not exist yet (no peer, including us, has published).
    return [];
  }
  const entries: Array<RosterEntry> = [];
  for (const name of files) {
    try {
      entries.push(JSON.parse(readFileSync(join(dir, name), 'utf8')) as RosterEntry);
    } catch (error) {
      log.warn(`readFolderEntries: bad entry ${name}: ${toLogFormat(error)}`);
    }
  }
  return entries;
}

// --- directory backend --------------------------------------------------------------

// The per-install secret that owns our directory entry (the directory refuses updates
// to an entry from anyone presenting a different one).
async function directorySecret(): Promise<string> {
  const existing = itemStorage.get('personasDirectorySecret');
  if (existing) {
    return existing;
  }
  const secret = randomBytes(32).toString('hex');
  await itemStorage.put('personasDirectorySecret', secret);
  return secret;
}

// One HTTPS call to the directory on our server. Same host, port and private CA as the
// chat server: the request goes through the localhost relay to the gateway.
function directoryRequest(
  method: 'GET' | 'PUT',
  path: string,
  body?: unknown,
  secret?: string
): Promise<unknown> {
  const { serverUrl, certificateAuthority } = window.SignalContext.config;
  const url = new URL(`${DIRECTORY_PATH}${path}`, serverUrl);
  const payload = body === undefined ? undefined : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method,
        ca: certificateAuthority,
        timeout: DIRECTORY_TIMEOUT_MS,
        headers: {
          ...(payload ? { 'content-type': 'application/json' } : {}),
          ...(secret ? { 'x-personas-directory-secret': secret } : {}),
        },
      },
      res => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          raw += chunk;
        });
        res.on('end', () => {
          const status = res.statusCode ?? 0;
          let parsed: unknown;
          let failure: Error | undefined;
          if (status >= 400) {
            failure = new Error(`directory ${method} ${path || '/'}: HTTP ${status} ${raw}`);
          } else {
            try {
              parsed = raw ? JSON.parse(raw) : undefined;
            } catch (error) {
              failure = error as Error;
            }
          }
          if (failure) {
            reject(failure);
          } else {
            resolve(parsed);
          }
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('directory request timed out')));
    req.on('error', reject);
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function publishToDirectory(): Promise<void> {
  const entry = await myEntry();
  if (!entry) {
    return;
  }
  try {
    const { aci, ...rest } = entry;
    await directoryRequest('PUT', `/${aci}`, rest, await directorySecret());
    log.info(`publishToDirectory: published ${entry.name} (${aci})`);
  } catch (error) {
    log.warn(`publishToDirectory: ${toLogFormat(error)}`);
  }
}

async function readDirectoryEntries(): Promise<Array<RosterEntry>> {
  try {
    const list = await directoryRequest('GET', '');
    if (!Array.isArray(list)) {
      return [];
    }
    // Untrusted input: keep only well-formed entries.
    return list.filter(
      (entry): entry is RosterEntry =>
        typeof entry?.aci === 'string' &&
        isAciString(entry.aci) &&
        typeof entry.e164 === 'string' &&
        (entry.profileKey === undefined || typeof entry.profileKey === 'string') &&
        (entry.name === undefined || typeof entry.name === 'string')
    );
  } catch (error) {
    log.warn(`readDirectoryEntries: ${toLogFormat(error)}`);
    return [];
  }
}

// --- seeding (both backends) --------------------------------------------------------

async function seedPeers(entries: Array<RosterEntry>): Promise<void> {
  const myAci = itemStorage.user.getAci();

  for (const entry of entries) {
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
    log.info(`seedPeers: seeded ${entry.name ?? entry.e164} (${entry.aci})`);

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

  if (process.env.PERSONAS_ROSTER_DIR) {
    log.info(`startPersonaRosterSync: using roster dir ${dir}`);
    drop(writeMyRosterEntry(dir));
    const poll = () => drop(seedPeers(readFolderEntries(dir)));
    poll();
    setInterval(poll, POLL_INTERVAL_MS);
    return;
  }

  log.info('startPersonaRosterSync: using the member directory');
  drop(publishToDirectory());
  const poll = async () => seedPeers(await readDirectoryEntries());
  drop(poll());
  setInterval(() => drop(poll()), POLL_INTERVAL_MS);
  setInterval(() => drop(publishToDirectory()), REPUBLISH_INTERVAL_MS);
}
