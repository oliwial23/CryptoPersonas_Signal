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


import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { drop } from '../util/drop.std.ts';
import {
  appliedPost,
  builtPersonasEngines,
  isPersonasEngineEnabled,
  isPostFlagged,
  getPollStatusLine,
} from './personasEngine.preload.ts';
import { runScheduledScans } from './personasActions.preload.ts';
import { decodePostText } from './personasCarriage.std.ts';
import { verifiedContextName } from './personasTopics.preload.ts';
import { hasOwnResetRequest } from './personasReset.preload.ts';
import { scanEpochMs } from './personasScanSchedule.std.ts';
import { maybeCompletePersonasReset } from './personasReset.preload.ts';
import { maybeContinueCatchUp } from './personasCatchUp.preload.ts';
import { hasJoinedPersonaGroup } from './personasMembership.preload.ts';
import { getTrackedPersonaPosts } from './personasRegistry.std.ts';

const log = createLogger('personasFlags');

// How often we re-read flags. Cheap (an in-memory engine lookup per tracked post), so
// it can be brisk enough that a ban visibly lands while you watch.
const REFRESH_INTERVAL_MS = 1_000;

// How often the loop checks whether a group's scan slot has come.
const SCAN_TICK_MS = 15_000;

// Scanning on the public schedule (personasScanSchedule) is ON by default, because a scan
// is how a member absorbs a ban, a badge or settled reputation, and a client that never
// scans eventually cannot post (NUM_INTS_BEFORE_SCAN). PERSONAS_AUTO_SCAN=off leaves only
// the persona menu's "Scan now".
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
    const message = window.MessageCache.getById(messageId);
    if (!message) {
      // Scrolled out of the cache; it will be re-tracked when reloaded.
      continue;
    }
    // The post's own group: each personas group has its own engine.
    const groupId = window.ConversationController.get(
      message.get('conversationId')
    )?.get('groupId');
    // A poll: its tally lives in the engine, and a ballot changes nothing on the message,
    // so copy the line across for the bubble to redraw.
    if (message.get('personaPoll')) {
      const status = getPollStatusLine(groupId, eh);
      if (status != null && status !== message.get('personaPollStatus')) {
        message.set({ personaPollStatus: status });
        // eslint-disable-next-line no-await-in-loop
        await window.MessageCache.saveMessage(message.attributes);
        changed += 1;
      }
      continue;
    }
    // A post the engine was holding when it arrived (personasEngine's
    // ingestRecordForTimeline): show it once it applies.
    if (message.get('personaPending')) {
      const applied = appliedPost(groupId, eh);
      if (!applied) {
        continue;
      }
      log.info(`refreshPersonaFlags: ${eh.slice(0, 12)}… applied; showing the held post`);
      const post = decodePostText(applied.body);
      message.set({
        body: post.text,
        personaClaim: applied.claim,
        personaContextName: verifiedContextName(groupId, eh, post.contextName),
        persona: applied.persona,
        personaAnonymous: applied.persona == null,
        personaFlagged: applied.flagged,
        personaPending: false,
      });
      // eslint-disable-next-line no-await-in-loop
      await window.MessageCache.saveMessage(message.attributes);
      changed += 1;
      continue;
    }

    const flagged = isPostFlagged(groupId, eh);
    if (flagged == null) {
      // The engine has no entry for this eh (it may have been rejected, or this
      // replica has not folded it yet). Leave the message as it is.
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

// Start both loops. The idle scan tends every personas group whose engine is built.
export function startPersonaFlagLoops(): void {
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
      // An admin-approved reset completes itself once the approval has landed.
      drop(maybeCompletePersonasReset());
      drop(maybeContinueCatchUp());
    }, REFRESH_INTERVAL_MS);
  }

  if (!scanInterval && isAutoScanEnabled()) {
    scanInterval = setInterval(() => drop(runDueScans()), SCAN_TICK_MS);
    drop(runDueScans());
  }

  log.info(
    `startPersonaFlagLoops: refresh every ${REFRESH_INTERVAL_MS}ms, ` +
      (isAutoScanEnabled()
        ? `one padded scan at the start of each ` +
          `${scanEpochMs(process.env.PERSONAS_SCAN_EPOCH_MS) / 60_000} min epoch`
        : 'scheduled scans OFF (PERSONAS_AUTO_SCAN=off)')
  );
}

let scanningDue = false;

// Make each group's scan for the epoch as soon as it begins: every interaction proves the
// object is from the current epoch, so this comes before anything else, and every member
// makes exactly one scan, at the same public time, whatever it holds. One scan is one
// proof padded to k_max slots, so no dummy scans are needed.
async function runDueScans(): Promise<void> {
  if (scanningDue) {
    return;
  }
  scanningDue = true;
  try {
    for (const [groupId, engine] of builtPersonasEngines()) {
      // Only a joined member has an object to bring up to date.
      const conversation = window.ConversationController.get(groupId);
      if (!conversation || !hasJoinedPersonaGroup(groupId)) {
        continue;
      }
      // A reset request names this object's nullifier. A scan would move on from the
      // object, and the admin's approval would then be refused.
      if (hasOwnResetRequest(groupId)) {
        continue;
      }
      if (!engine.epochScanNeeded() && !engine.isScanning()) {
        continue;
      }
      // oxlint-disable-next-line no-await-in-loop
      await runScheduledScans(conversation, 1).catch(error =>
        log.error(`epoch scan failed: ${toLogFormat(error)}`)
      );
    }
  } finally {
    scanningDue = false;
  }
}
