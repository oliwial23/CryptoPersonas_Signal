// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 6 — keeping the REVOCATION FLAG live, and emitting the scans
// that produce it.
//
// The rendering gate says a revoked persona's posts are shown FLAGGED, never deleted.
// Phase 4 stamped `personaFlagged` onto a message at ingest time, which is correct but
// only ever right at that instant: a ban settles later, by definition — a poll has to
// stay open for `settlementBarriers` barriers first. So every post ingested BEFORE the
// ban settled kept `personaFlagged: false` forever, and the flag never actually
// appeared in the UI.
//
// Two things run here:
//
//   * a MANUAL SCAN action — `emitScan` absorbs the revocation callbacks fired since
//     our last scan. Without it a settled ban never enters our replica's view at all.
//   * a FLAG refresher — re-reads `logEntry(eh).flagged` for the persona posts we
//     have on screen and updates any message whose flag changed. `message.set` feeds
//     Signal's own redux update path, so the bubble re-renders itself.
//
// The eh -> messageId registry lives in personasRegistry.std.ts so that the modules
// which only need to RECORD a post (notably the conversation model) do not have to
// import the native ZK addon transitively.

import type { ConversationModel } from '../models/conversations.preload.ts';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { drop } from '../util/drop.std.ts';
import {
  isPersonasEngineEnabled,
  isPostFlagged,
} from './personasEngine.preload.ts';
import { getTrackedPersonaPosts } from './personasRegistry.std.ts';

const log = createLogger('personasFlags');

// How often we re-read flags. Cheap (an in-memory engine lookup per tracked post), so
// it can be brisk enough that a ban visibly lands while you watch.
const REFRESH_INTERVAL_MS = 2_000;

// Re-read the engine's flag for every tracked post and push any change onto the
// message. Returns how many messages changed (for logging).
async function refreshPersonaFlags(): Promise<number> {
  const tracked = getTrackedPersonaPosts();
  if (!isPersonasEngineEnabled() || tracked.size === 0) {
    return 0;
  }

  let changed = 0;
  for (const [eh, messageId] of tracked) {
    const flagged = isPostFlagged(eh);
    if (flagged == null) {
      // The engine has no entry for this eh (it may have been rejected, or this
      // replica has not folded it yet). Leave the message as it is.
      continue;
    }

    const message = window.MessageCache.getById(messageId);
    if (!message) {
      // Scrolled out of the cache; it will be re-tracked when reloaded.
      continue;
    }
    if (Boolean(message.get('personaFlagged')) === flagged) {
      continue;
    }

    log.info(
      `refreshPersonaFlags: ${eh.slice(0, 12)}… flagged=${flagged} (persona revoked)`
    );
    message.set({ personaFlagged: flagged });
    // eslint-disable-next-line no-await-in-loop
    await window.MessageCache.saveMessage(message.attributes);
    changed += 1;
  }

  return changed;
}

let refreshInterval: NodeJS.Timeout | undefined;

// Start both loops. `getConversation` is injected so this module does not have to
// guess which conversation the demo group is — the caller supplies the currently
// selected one, which in the demo is the persona group.
export function startPersonaFlagLoops(
  getConversation: () => ConversationModel | undefined
): void {
  if (!isPersonasEngineEnabled()) {
    return;
  }

  if (!refreshInterval) {
    refreshInterval = setInterval(() => {
      drop(
        refreshPersonaFlags().catch(error =>
          log.error(`flag refresh failed: ${toLogFormat(error)}`)
        )
      );
    }, REFRESH_INTERVAL_MS);
  }

  log.info(
    `startPersonaFlagLoops: refresh every ${REFRESH_INTERVAL_MS}ms, scans are manual`
  );
}
