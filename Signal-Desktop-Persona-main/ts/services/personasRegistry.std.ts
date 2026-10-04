// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the envelope-hash -> messageId registry, deliberately kept in its own
// dependency-free module.
//
// The flag refresher (personasFlags) needs this map, and so do the two places that
// learn about a persona post: the receive seam and `enqueueMessageForSend` on the
// conversation model. But personasFlags transitively pulls in the ZK engine, which
// `require`s the native addon at module load and THROWS if the platform binary is
// absent. `ts/models/conversations.preload.ts` is core Signal code; it has no business
// acquiring a native-addon dependency just to remember a string pair.
//
// So the map lives here — no engine, no Signal imports, nothing to fail — and only the
// modules that genuinely need the engine import the engine.
//
// In memory only. It is rebuilt as messages are ingested or sent, and the demo backend
// is ephemeral anyway.

const messageIdByEh = new Map<string, string>();

// Note a persona post so its revocation flag can be kept current.
export function trackPersonaPost(eh: string, messageId: string): void {
  if (!eh || !messageId) {
    return;
  }
  messageIdByEh.set(eh, messageId);
}

// Every tracked (eh, messageId) pair, for the flag refresher to walk.
export function getTrackedPersonaPosts(): ReadonlyMap<string, string> {
  return messageIdByEh;
}
