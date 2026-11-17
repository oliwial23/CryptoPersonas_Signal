// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// WHEN a member scans. Time is cut into public epochs on the group's shared schedule, and
// every interaction proves the member's object is from the current epoch. So each member
// scans once, at the start of every epoch, before anything else, whatever it holds: the
// scan's timing says nothing about what the member did. A scan is one proof padded to
// k_max slots, so its size says nothing either, and no dummy scans are needed. (Members
// used to scan at a random moment and pad the COUNT of single-ticket scans to 36.)

const DEFAULT_SCAN_EPOCH_MS = 24 * 60 * 60 * 1_000;
const DEFAULT_SCANS_PER_EPOCH = 1;

// The epoch length: a day, or PERSONAS_SCAN_EPOCH_MS for a demo. A ban or badge reaches
// an honest member's object at its next slot, so this is also how long that can take.
export function scanEpochMs(override?: string): number {
  const parsed = Number(override);
  return parsed > 0 ? parsed : DEFAULT_SCAN_EPOCH_MS;
}

// Scans per member per epoch: PERSONAS_SCANS_PER_EPOCH, or enough for a sweep of the
// tickets a busy member holds over the ban window.
export function scansPerEpoch(override?: string): number {
  const parsed = Number(override);
  return Number.isInteger(parsed) && parsed > 0
    ? parsed
    : DEFAULT_SCANS_PER_EPOCH;
}

export function scanEpochAt(
  nowMs: number,
  anchorMs: number,
  epochMs: number
): number {
  return Math.floor((nowMs - anchorMs) / epochMs);
}

// A random moment between `nowMs` and the end of the epoch `nowMs` is in, for `random` in
// [0, 1). Starting from now, not the start of the epoch, so that a client that opens
// partway through still scans in this epoch.
export function pickScanSlot(
  nowMs: number,
  anchorMs: number,
  epochMs: number,
  random: number
): number {
  const epochEnd =
    anchorMs + (scanEpochAt(nowMs, anchorMs, epochMs) + 1) * epochMs;
  return nowMs + Math.floor(random * (epochEnd - nowMs));
}
