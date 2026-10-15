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

// --- the timestamp an own record is placed by ------------------------------------------
//
// Every replica must place a record on the SAME barrier, or replicas disagree about when
// a settlement happened, scans are rejected as stale, and members fork. Recipients used
// to bucket a record by the server's receive time, which its SENDER never learns — the
// sender bucketed its own copy by its local clock at emit time instead, and near a barrier
// boundary (or with a second of clock skew) the two disagreed.
//
// So the sender now decides: it places its own record at `stampOwnRecord`'s timestamp
// and sends the Signal message with exactly that timestamp (enqueueMessageForSend reads
// it back with `takeOwnRecordSentAt`), and recipients bucket by the message's sent
// timestamp (personasBarrier `recordTimestamp`). Strictly increasing per process, so two
// records never share a Signal timestamp.
const ownRecordSentAt = new Map<string, number>();
let lastOwnSentAt = 0;

export function stampOwnRecord(recordBase64: string): number {
  const sentAt = Math.max(Date.now(), lastOwnSentAt + 1);
  lastOwnSentAt = sentAt;
  ownRecordSentAt.set(recordBase64, sentAt);
  return sentAt;
}

export function takeOwnRecordSentAt(recordBase64: string | undefined): number | undefined {
  if (!recordBase64) {
    return undefined;
  }
  const sentAt = ownRecordSentAt.get(recordBase64);
  ownRecordSentAt.delete(recordBase64);
  return sentAt;
}
