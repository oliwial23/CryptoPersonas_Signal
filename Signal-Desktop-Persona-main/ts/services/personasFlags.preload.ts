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
//   * a SCAN loop — `emitScan` absorbs the revocation callbacks fired since our last
//     scan. Without it a settled ban never enters our replica's view at all.
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
import { sendPersonaScan } from './personasActions.preload.ts';
import { hasJoinedPersonaGroup } from './personasMembership.preload.ts';
import { getTrackedPersonaPosts } from './personasRegistry.std.ts';

const log = createLogger('personasFlags');

// How often we re-read flags. Cheap (an in-memory engine lookup per tracked post), so
// it can be brisk enough that a ban visibly lands while you watch.
const REFRESH_INTERVAL_MS = 2_000;

// The IDLE CATCH-UP interval. Scanning now happens primarily on send (see the composer
// duck), which covers any member who is actually talking. This timer exists only for a
// client that sits open for days without sending anything: it should still absorb a
// revocation aimed at it rather than carrying it indefinitely.
//
// 24 hours rather than 30 seconds because a scan is a synchronous Groth16 proof on the
// render process's main thread. At 30s intervals that is a constant background cost and
// a constant stream of records for no benefit; the send-time scan is what keeps a
// talking member current.
const SCAN_INTERVAL_MS = 24 * 60 * 60 * 1_000;

// Automatic scanning is OFF by default.
//
// A scan is the most expensive thing this integration does: `emitScan` is a synchronous
// Groth16 proof on the render process's main thread, and it puts a record on the wire.
// Doing that every 30 seconds forever — whether or not anything is outstanding — is a
// lot of background work and a lot of traffic for a demo, and it makes the timeline of
// "what caused what" hard to follow when you are explaining the protocol to someone.
//
// With it off, scans happen only when a human picks persona menu -> "Scan now".
//
// WHAT THIS CHANGES, and it is not cosmetic: a scan is how a member ABSORBS the
// revocation callbacks fired at them. Post flags do not depend on it — those come from
// barrier settlement in the replica's own rebuild — but a banned member's own object is
// only marked banned once THEY scan. So with automatic scanning off, a revoked member
// keeps being able to post until someone clicks Scan now on their instance. In a demo
// that is arguably clearer (you show the ban landing on a keystroke), but it is a real
// behavioural difference from the protocol's intent, where scanning is continuous.
//
// Set PERSONAS_AUTO_SCAN=1 to restore the old loop.
export function isAutoScanEnabled(): boolean {
  const raw = process.env.PERSONAS_AUTO_SCAN?.trim();
  // 'off' disables the idle catch-up entirely; anything else leaves it on. The default
  // is ON, because the 24h timer is cheap and a client that never scans eventually
  // cannot post (NUM_INTS_BEFORE_SCAN = 200).
  return raw !== '0' && raw?.toLowerCase() !== 'off' && raw?.toLowerCase() !== 'false';
}

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
let scanInterval: NodeJS.Timeout | undefined;

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

  if (!scanInterval && isAutoScanEnabled()) {
    scanInterval = setInterval(() => {
      // Only a joined member has callbacks to absorb, and only then is a scan record
      // acceptable to the other replicas.
      if (!hasJoinedPersonaGroup()) {
        return;
      }
      const conversation = getConversation();
      if (!conversation) {
        return;
      }
      drop(
        sendPersonaScan(conversation).catch(error =>
          log.error(`scan failed: ${toLogFormat(error)}`)
        )
      );
    }, SCAN_INTERVAL_MS);
  }

  log.info(
    `startPersonaFlagLoops: refresh every ${REFRESH_INTERVAL_MS}ms, ` +
      (isAutoScanEnabled()
        ? `idle catch-up scan every ${SCAN_INTERVAL_MS / 3_600_000}h (scans also run on send)`
        : 'idle catch-up scan OFF (PERSONAS_AUTO_SCAN=off)')
  );
}
