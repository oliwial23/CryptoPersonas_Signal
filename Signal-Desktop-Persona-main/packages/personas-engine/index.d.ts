// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

/// <reference types="node" />

export interface EngineOptions {
  /**
   * Directory holding (or to generate) the ~51 MB Merkle-mode Groth16 key bundle.
   * The first engine to touch a fresh dir pays the (minutes-long) keygen; later
   * ones load the cache in ~100 ms. Share one dir across members.
   */
  dataDir: string;
  /** Conversation id these records belong to. Defaults to `"personas"`. */
  conversation?: string;
  /** `true` (default) builds a member that can emit; `false` an observer. */
  member?: boolean;
  /** Deterministic RNG seed for reproducible runs; omit for OS entropy. */
  seed?: number;
  /** Replica accept-rule config (defaults: 256 / 3 / 1). */
  rootWindow?: number;
  settlementBarriers?: number;
  pollCloseBarriers?: number;
  /**
   * Shared barrier schedule (§14). Set both to bucket ingests by service
   * timestamp; omit for the local-barrier cadence driven by explicit `barrier()`.
   */
  heartbeatAnchorMs?: number;
  heartbeatPeriodMs?: number;
}

/** A record produced by an `emit*` call. */
export interface Emitted {
  /** The CBOR record bytes to carry (plaintext; Desktop encrypts + delivers). */
  bytes: Buffer;
  /** Envelope hash (lowercase hex) — the handle for polls/ratings. */
  eh: string;
  /** Persona petname shown in the sender slot, or undefined for anonymous. */
  persona?: string;
}

/** The accept-rule outcome of an ingest. */
export interface IngestStatus {
  status: 'applied' | 'buffered' | 'rejected';
  /** Present when `status === 'rejected'`. */
  reason?: string;
  /** The ingested record's envelope hash (hex); use `logEntry` to fetch its post. */
  eh: string;
}

/** One structured chat-log entry, for the UI. */
export interface LogEntry {
  eh: string;
  kind: string;
  /** Persona petname, or undefined for an anonymous post. */
  author?: string;
  body: string;
  /** True once the author's persona was revoked; render flagged, never delete. */
  flagged: boolean;
}

/**
 * The personas ZK engine: a production-height (32/32/32) Replica plus an optional
 * Member. `emit*` produce record bytes with real Groth16 proofs (the plaintext
 * Desktop encrypts); `ingest` verifies + folds a record that arrived over Desktop.
 * No Signal crypto lives here.
 */
export class Engine {
  constructor(options: EngineOptions);

  /** Emit a join record (a member advertising itself to the group). */
  emitJoin(): Emitted;
  /** Emit a pseudonymous post under `context`. Real Groth16 proof — seconds. */
  emitPostPseudo(body: string, context: number): Emitted;
  /** Emit an anonymous post (no linkable persona). */
  emitPostAnon(body: string): Emitted;
  /** Emit as the `i`-th rate-limited persona for `context` (distinct petname per i). */
  emitPostPseudoRate(body: string, context: number, i: number): Emitted;
  /** Open a poll; `target` (hex eh) is the reviewed post for a ban poll. */
  emitPoll(
    question: string,
    options: Array<string>,
    kind: 'ban' | 'standard',
    target?: string
  ): Emitted;
  /** Cast a ballot in the poll named by hex eh. */
  emitVote(poll: string, option: number): Emitted;
  /** Rate the record named by hex eh by `delta`. */
  emitRate(target: string, delta: number): Emitted;
  /** Emit a scan absorbing callbacks invoked since the last scan. */
  emitScan(): Emitted;

  /**
   * Ingest a record that arrived over Desktop. `receivedAtMs` is the service
   * receive timestamp for barrier bucketing; pass 0 for the local-barrier path.
   */
  ingest(record: Buffer, receivedAtMs: number): IngestStatus;

  /** Accepted chat log as display lines (`~petname: msg`, flagged where revoked). */
  render(): Array<string>;
  /** Open and recently-closed polls as status lines. */
  renderPolls(): Array<string>;
  /** Accepted log as structured entries. */
  log(): Array<LogEntry>;
  /** The chat-log entry for an envelope hash (hex), or undefined if not a post. */
  logEntry(eh: string): LogEntry | undefined;

  /** Cross exactly one settlement barrier by hand. */
  barrier(): void;
  /** Advance to the barrier the shared schedule says `nowMs` reached; returns it. */
  tick(nowMs: number): number;

  /** Convergence fingerprint: the three replica roots as concatenated hex. */
  fingerprint(): string;
  /** The barrier this replica is currently at. */
  currentBarrier(): number;
  /**
   * This member's own reputation, or undefined for an observer / not-yet-joined
   * engine. This is the READ side of `emitRate` — without it, ratings move a value
   * nobody can see.
   *
   * Only ever OUR OWN: a member's reputation lives in their own user object, and the
   * serverless protocol carries reputation as proof-carrying rate records rather than
   * a queryable directory, so there is no way to read another member's from here.
   */
  getReputation(): string | undefined;
}

declare const addon: { Engine: typeof Engine };
export default addon;
