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
  /** A member's saved private state (exportMemberState) to continue as. SECRET. */
  memberState?: Buffer;
  /** A file to journal every seen record to, and to restore the replica from. */
  journalPath?: string;
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
  /**
   * Join as `account` (the ACI, 32 hex characters without dashes), proving this
   * member's object is fresh. Accepted once per account, plus once per admin approval.
   */
  emitJoin(account: string): Emitted;
  /** As a group admin: allow `account` one more join. Send it under your own account. */
  emitRejoinApprove(account: string): Emitted;
  /** A reset request's proof: not banned and just swept, as `account`. */
  proveNotBanned(account: string): Buffer;
  /** The account a reset-request proof is for, if it verifies against our tree. */
  verifyNotBanned(proof: Buffer): string | null;
  /** Start over with a fresh object (after an approved re-join). */
  resetMember(): void;
  /** Joins applied and re-joins approved for `account`. */
  joinCounts(account: string): { joins: number; approved: number };
  /** For a join or re-join approval: which, and the account it names (hex). */
  recordAccountClaim(record: Buffer): { kind: 'join' | 'rejoin-approve'; account: string } | null;
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
  getReputation(): number | undefined;
  /** Is a callback sweep unfinished? While true, every proving flow except scan aborts. */
  /**
   * Prove two of MY pseudonyms share an author. Args are the two CONTEXTS (for an
   * unlimited pseudonym, its nonce). Returns the encoded proof + public inputs.
   */
  emitAuthorship(contextA: number, contextB: number): Buffer;
  /**
   * Verify an authorship proof. Returns the two petnames the proof ACTUALLY proves
   * about, derived from its own public inputs — render these, never names from the
   * wire — or null if it does not verify.
   */
  verifyAuthorship(proof: Buffer): { first: string; second: string } | null;
  /** Request a badge: 1=Faculty, 2=Student, 3=Industry. Files a ticket to approve. */
  emitBadgeRequest(slot: number): JsEmitted;
  /** Approve a badge request by its envelope hash. */
  emitBadgeApprove(request: string, slot: number): JsEmitted;
  /** Prove possession of a badge by NAME. Returns the encoded proof. */
  emitBadgeProof(badge: string): Buffer;
  /** Verify a badge proof; returns the badge NAME it proves, or null. */
  verifyBadgeProof(proof: Buffer): string | null;
  /** Badge requests not yet approved, for an admin to act on. */
  pendingBadgeRequests(): Array<{ eh: string; slot: number }>;
  /**
   * Badges actually HELD in my zk object (not the decorative label a post carries).
   * Arrives via approval -> my next scan. Empty for an observer.
   */
  getBadges(): Array<string>;
  /** Am I banned? undefined for an observer with no member object. */
  isBanned(): boolean | undefined;
  isScanning(): boolean;
  /** Callbacks still outstanding mid-sweep; scan until this reaches zero. */
  outstandingCallbacks(): number;
  /**
   * This member's private state, to save ENCRYPTED and pass back as `memberState`.
   * Save after every emit and before sending; while a scan is prepared, this is the
   * pre-scan state.
   */
  exportMemberState(): Buffer | null;
  /**
   * Whether a scan would absorb anything now: a sweep is unfinished, a callback of ours
   * was invoked (ban, badge, settled reputation), or we near the interaction cap.
   */
  scanNeeded(): boolean;
  /** Scans left to finish the sweep in progress (0 when not scanning). */
  sweepRemaining(): number;
  /** Whether this member's current object is on the bulletin (joined, in sync). */
  memberOnBulletin(): boolean;
  /** Prove a scan without releasing it; returns its eh. Blocks every other emit. */
  prepareScan(): string;
  /** Whether the prepared scan's callback roots are still current. */
  scanStillValid(): boolean;
  /** Release the prepared scan and return it to send. Irrevocable. */
  commitScan(): Emitted;
  /** Abandon the prepared (never released) scan, restoring the pre-scan object. */
  discardScan(): void;
}

declare const addon: { Engine: typeof Engine };
export default addon;
