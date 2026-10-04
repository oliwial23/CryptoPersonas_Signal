// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Which badge this instance is currently CLAIMING, persisted per instance.
//
// Read personasBadges.std.ts first: the claim is unverified and unenforced. This module
// is deliberately thin — a label in a file — because that is genuinely all a display
// claim is. There is no grant, no approval, no proof, and nothing to verify, so there is
// nothing here to get subtly wrong.
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
