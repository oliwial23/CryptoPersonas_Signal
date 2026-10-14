// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Which badge this instance is currently claiming, persisted per instance — and, more
// importantly, whether it is entitled to.
//
// THE SELECTION IS A PREFERENCE, NOT AN ENTITLEMENT. That distinction is the whole of
// this module's remaining subtlety, and getting it wrong produced a real bug: the
// composer menu was narrowed to offer only badges the member actually holds, but the
// SEND PATH read this file directly, so a label written here by an earlier build — or
// simply selected before the badge was approved — rode out on every post. The menu is
// presentation; the file is a preference; neither is a check. Possession is only ever
// what the member's own zk object says, which is why `getSelectedBadgeIfHeld` and not
// `getSelectedBadge` is what the send path is allowed to call.
//
// The file persists across `personas-run.sh --reset`, by design (see below), which is
// exactly why a stale entitlement here outlives the state that would have justified it.
//
// Stored beside the roster rather than in Signal's own storage so that wiping a demo
// instance's userData (`personas-run.sh --reset`) does not silently drop the badge you
// picked for the demo, and so the file is easy to inspect when you are explaining that
// the badge really is just a string on disk.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { getRosterDir } from '../textsecure/personaRoster.preload.ts';
import { isPersonaBadge, type PersonaBadge } from './personasBadges.std.ts';
import { heldBadges } from './personasEngine.preload.ts';

const log = createLogger('personasBadgeState');

// Per-instance: two members in one demo will normally claim different badges, and the
// roster dir is shared, so the instance name has to be in the filename.
function badgeFile(): string | undefined {
  const dir = getRosterDir();
  if (!dir) {
    return undefined;
  }
  const instance = process.env.NODE_APP_INSTANCE?.trim() || 'default';
  return join(dir, `personas-badge-${instance}.json`);
}

let cached: PersonaBadge | undefined;
let loaded = false;

export function getSelectedBadge(): PersonaBadge | undefined {
  if (loaded) {
    return cached;
  }
  loaded = true;
  const path = badgeFile();
  if (!path) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as {
      badge?: unknown;
    };
    // Validated against the known labels on the way IN from disk, so a hand-edited file
    // cannot put arbitrary text next to someone's name. This is presentation hygiene,
    // not a security boundary — a peer can still send any label it likes, and the chip
    // renders what it is given.
    cached = isPersonaBadge(parsed?.badge) ? parsed.badge : undefined;
  } catch {
    // No file yet is the normal case, not an error.
    cached = undefined;
  }
  return cached;
}

/**
 * The selected badge, but ONLY if this member's zk object actually contains it.
 *
 * This is the function the send path must use. `getSelectedBadge` answers "what did
 * this instance pick?", which is a question about a file; this one answers "what is
 * this instance entitled to claim?", which is a question about the member's own
 * object — and only the second one may reach the wire.
 *
 * Returns undefined, silently, when the selection is not held. A toast on every send
 * would be noise, and the composer already shows `Badge: none held`; the log line is
 * there for the case where someone is wondering where their badge went.
 */
export function getSelectedBadgeIfHeld(): PersonaBadge | undefined {
  const selected = getSelectedBadge();
  if (!selected) {
    return undefined;
  }
  const held = heldBadges();
  if (held.includes(selected)) {
    return selected;
  }
  log.warn(
    `getSelectedBadgeIfHeld: ${selected} is selected but NOT held ` +
    `(held: ${held.length > 0 ? held.join(', ') : 'none'}); ` +
    'dropping the claim rather than sending an unearned badge'
  );
  return undefined;
}

export function setSelectedBadge(badge: PersonaBadge | undefined): void {
  cached = badge;
  loaded = true;
  const path = badgeFile();
  if (!path) {
    return;
  }
  try {
    const dir = getRosterDir();
    if (dir) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(path, JSON.stringify({ badge: badge ?? null }, null, 2), 'utf8');
    log.info(`setSelectedBadge: now ${badge ?? 'none'}`);
  } catch (error) {
    // Non-fatal: the in-memory value still applies for this session.
    log.error(`setSelectedBadge: persist failed: ${toLogFormat(error)}`);
  }
}
