// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the bridge between Signal-Desktop and the CryptoPersonas ZK engine
// (`@signalapp/personas-engine`, a napi addon over the transport-agnostic
// Replica + Member). Desktop is the transport: `emit*` produce record bytes with
// real Groth16 proofs that we carry as an ordinary message body, and every incoming
// body is checked for a record to `ingest`. No Signal crypto lives here.
//
// This is the Phase 3 "attributable bring-up": records ride over Desktop's real
// send/receive path, the sender still its own real account. Recipient-anonymity
// (the shared phantom identity) is Phase 5.
//
// Gated on PERSONAS_AUTO_REGISTER / PERSONAS_KEYS_DIR so normal builds are inert.

import { homedir } from 'node:os';
import { join } from 'node:path';

import { Engine } from '@signalapp/personas-engine';
import type { IngestStatus, Emitted } from '@signalapp/personas-engine';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import { badgeSlotFromLogBody } from './personasBadgeRules.std.ts';
import {
  encodeRecordBody,
  encodeBadgeBody,
  encodePollBody,
  encodeVoteBody,
  encodeRateBody,
  decodeRecordBody,
  decodePollDescriptor,
  type PersonaChoice,
  type PersonaPollDescriptor,
  encodeAuthorshipProof,
  encodeBadgeProof,
} from './personasCarriage.std.ts';
import { hasPhantomMaterial } from './personasPhantom.preload.ts';
import {
  getBarrierSchedule,
  ingestTimestampFor,
  startBarrierTicker,
} from './personasBarrier.preload.ts';

export {
  PERSONAS_MARKER,
  encodeRecordBody,
  decodeRecordBody,
} from './personasCarriage.std.ts';
export type {
  PersonaChoice,
  PersonaPollDescriptor,
} from './personasCarriage.std.ts';

const log = createLogger('personasEngine');

// One shared conversation label for the demo group (the engine is single-conversation;
// the id is just a tag). All members must use the same value.
const PERSONAS_CONVERSATION = 'personas-demo';

const DEFAULT_KEYS_DIR = join(homedir(), '.personas-demo-keys');

export function isPersonasEngineEnabled(): boolean {
  return Boolean(
    process.env.PERSONAS_AUTO_REGISTER || process.env.PERSONAS_KEYS_DIR
  );
}

function getKeysDir(): string {
  return process.env.PERSONAS_KEYS_DIR?.trim() || DEFAULT_KEYS_DIR;
}

let engine: Engine | undefined;
let constructionFailed = false;

// The engine singleton for this instance (one Member per process). Built lazily on
// first use; construction reads the ~51MB key bundle and mints this member's
// keypair. Returns undefined if disabled or if construction failed (so callers
// never crash the message pipeline).
export function getPersonasEngine(): Engine | undefined {
  if (engine || constructionFailed || !isPersonasEngineEnabled()) {
    return engine;
  }
  // Wait for the phantom bundle: it carries the barrier schedule every member must
  // share, and the replica's schedule is fixed at construction. Background warms the
  // engine again the moment the bundle is minted or adopted.
  if (!hasPhantomMaterial()) {
    return undefined;
  }
  const dataDir = getKeysDir();
  // Phase 6: put the replica on the SHARED barrier schedule when there is a roster
  // dir to agree through. Every member then buckets an ingest by the record's
  // service timestamp rather than local arrival order, so replicas stay converged
  // AND settlement barriers actually pass — which is what lets a ban poll close and
  // a revoked persona's posts flag. Without a schedule we keep the old local-barrier
  // cadence (a lone instance has nobody to agree with).
  const schedule = getBarrierSchedule();
  try {
    engine = new Engine({
      dataDir,
      conversation: PERSONAS_CONVERSATION,
      ...(schedule
        ? {
            heartbeatAnchorMs: schedule.anchorMs,
            heartbeatPeriodMs: schedule.periodMs,
          }
        : {}),
    });
    log.info(
      `constructed engine (keys: ${dataDir}; ${
        schedule
          ? `shared barrier schedule anchor=${schedule.anchorMs} period=${schedule.periodMs}ms`
          : 'local-barrier cadence'
      })`
    );
    // Advance the replica along the schedule so settlement happens on time even in a
    // silent group. No-op when there is no shared schedule.
    startBarrierTicker(nowMs => engine?.tick(nowMs));
  } catch (error) {
    constructionFailed = true;
    log.error(`failed to construct engine: ${toLogFormat(error)}`);
  }
  return engine;
}

// Warm the engine at boot so first send/receive is instant and so a failure is
// visible early. Safe to call unconditionally; a no-op when disabled.
export function warmPersonasEngine(): void {
  if (!isPersonasEngineEnabled()) {
    return;
  }
  getPersonasEngine();
}

// The result of examining an incoming message body for a personas record.
export type RecordIngestResult =
  // Ordinary chatter — let it flow through the normal message pipeline untouched.
  | { kind: 'not-record' }
  // A record that produced nothing to render (a join/vote/rate/scan, or one
  // buffered / rejected) — keep it out of the timeline, but it is not a chat message.
  | { kind: 'ingested' }
  // A post to render: stamp these onto the message and show it as a persona bubble.
  | {
      kind: 'post';
      eh: string;
      persona?: string;
      body: string;
      flagged: boolean;
    }
  // A poll to render as its own bubble. `eh` is the handle a ballot references.
  | { kind: 'poll'; eh: string; descriptor: PersonaPollDescriptor }
  // A badge REQUEST, to render as a notification an admin can approve in place. `eh`
  // is the handle the approval names, so the Approve button needs nothing else.
  //
  // This needs its own kind because the replica logs a request like any other entry,
  // with `kind: "BadgeRequest"` and a body of `"requested badge slot 1"`. Without the
  // branch it fell through to `kind: 'post'` below and every member saw a persona
  // bubble containing that internal string — the "weird automated message" that made
  // the whole flow unexplainable from the UI.
  | { kind: 'badge-request'; eh: string; slot: number }
  // A badge APPROVAL, rendered so the requester learns they have one to collect.
  | { kind: 'badge-approve'; eh: string; slot: number };

// Receive seam for the timeline: ingest a record body and describe what to render.
// `serverTimestampMs` is the SERVICE receive timestamp; on the shared barrier
// schedule it is what buckets the record onto a barrier every member agrees about
// (see personasBarrier). Never throws. A record body is always kept out of the raw
// timeline (`not-record` is returned only for genuine non-records).
export function ingestRecordForTimeline(
  body: string | undefined | null,
  serverTimestampMs: number
): RecordIngestResult {
  const record = decodeRecordBody(body);
  if (!record) {
    return { kind: 'not-record' };
  }
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    log.warn('ingestRecordForTimeline: record arrived but engine unavailable');
    return { kind: 'ingested' };
  }
  try {
    const status: IngestStatus = currentEngine.ingest(
      record,
      ingestTimestampFor(serverTimestampMs)
    );
    log.info(
      `ingested record: ${status.status}${status.reason ? ` (${status.reason})` : ''}`
    );

    // A poll carries its display descriptor in the carriage (the engine hands back
    // no option labels), so render it from there — keyed by the eh the engine just
    // gave us, which is the handle a ballot must reference.
    const descriptor = decodePollDescriptor(body);
    if (descriptor) {
      return { kind: 'poll', eh: status.eh, descriptor };
    }

    const entry = currentEngine.logEntry(status.eh);
    if (!entry) {
      return { kind: 'ingested' };
    }

    // Badge records are NOT posts, even though the replica logs them as entries with a
    // body. Branch before the post fallthrough below, or their internal body text gets
    // rendered as somebody's message.
    if (entry.kind === 'BadgeRequest' || entry.kind === 'BadgeApprove') {
      const slot = badgeSlotFromLogBody(entry.body);
      if (slot == null) {
        // The body format is ours, so this should not happen — but guessing a slot
        // would put a wrong badge name in front of an admin about to grant it.
        log.error(
          `ingestRecordForTimeline: could not read a slot out of a ${entry.kind} ` +
          `body (${JSON.stringify(entry.body)}); not rendering it`
        );
        return { kind: 'ingested' };
      }
      return {
        kind: entry.kind === 'BadgeRequest' ? 'badge-request' : 'badge-approve',
        eh: status.eh,
        slot,
      };
    }

    return {
      kind: 'post',
      eh: status.eh,
      persona: entry.author,
      body: entry.body,
      flagged: entry.flagged,
    };
  } catch (error) {
    log.error(`ingestRecordForTimeline failed: ${toLogFormat(error)}`);
    return { kind: 'ingested' };
  }
}

// Emit + self-ingest a record (a member's own replica must contain its own records),
// returning the record ready to carry. Used for protocol records (join/rate/vote/scan)
// and dev helpers where the whole body is the record.
export function emitAndSelfIngest(
  produce: (engine: Engine) => Emitted
): { emitted: Emitted; body: string } | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  const emitted = produce(currentEngine);
  // Our own record never went to the server, so there is no service timestamp;
  // ingestTimestampFor falls back to local wall-clock on the shared schedule (and to
  // the local-barrier 0 when there is no schedule).
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(undefined));
  return { emitted, body: encodeRecordBody(emitted.bytes) };
}

// The fields the send path needs for a persona post: the plaintext to display,
// the persona petname (undefined for anonymous), the envelope hash (the handle a
// rating or ban poll targets), and the base64 record to put on the wire in place of
// the plaintext.
export type PersonaPostSend = {
  body: string;
  persona?: string;
  eh: string;
  personaRecordBase64: string;
};

// Compose a persona post: emit the record (with a real Groth16 proof), self-ingest
// it, and return what to send. The message displays `body` (plaintext) everywhere
// while the wire carries the record — the send path swaps them via
// `personaRecordBase64`. Returns undefined if the engine is unavailable.
export function composePersonaPost(
  text: string,
  choice: PersonaChoice
): PersonaPostSend | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  try {
    if (choice.kind === 'anon') {
      emitted = currentEngine.emitPostAnon(text);
    } else if (choice.kind === 'rate') {
      // Topic-scoped and rate-limited: persona = H(sk || context || index), with
      // index < MAX_PSEUDO. The context comes from the topic registry, so all
      // members derive comparable personas for the same topic.
      emitted = currentEngine.emitPostPseudoRate(
        text,
        choice.context,
        choice.index
      );
    } else {
      // The UNLIMITED plain pseudonym: no topic. A member may mint as many of these
      // as they like, so the fresh random nonce is what makes each one a distinct,
      // unlinkable petname.
      emitted = currentEngine.emitPostPseudo(text, choice.nonce);
    }
  } catch (error) {
    log.error(`composePersonaPost: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  // Our own record; no service timestamp exists yet (see emitAndSelfIngest).
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(undefined));
  return {
    body: text,
    persona: emitted.persona ?? undefined,
    eh: emitted.eh,
    personaRecordBase64: Buffer.from(emitted.bytes).toString('base64'),
  };
}

// ---------------------------------------------------------------------------
// The rest of the record surface: rate, poll, vote, scan.
//
// These were reachable only from the engine addon before — nothing in the app
// emitted them, which meant reputation could not move, a poll could not be opened,
// and a ban could not be voted. Each helper emits + self-ingests and returns the body
// to carry; the caller (personasActions) sends it attributably.
// ---------------------------------------------------------------------------

// Rate the record `targetEh` by `delta` (conventionally +1 / -1). Reputation is what
// a ban poll ultimately acts on, so this is the ordinary feedback path.
// Rate the record `targetEh` by `delta`. Like a ballot, this is PSEUDONYMOUS in
// circuit — `member.rate` derives the rater as `H(sk, target.context())` with no
// nonce, giving one rating per member per target, unlinkable across targets. So it
// rides the phantom: an attributable envelope would name the rater outright.
export function composePersonaRate(
  targetEh: string,
  delta: number
): { eh: string; body: string } | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  try {
    emitted = currentEngine.emitRate(targetEh, delta);
  } catch (error) {
    log.error(`composePersonaRate: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(undefined));
  return { eh: emitted.eh, body: encodeRateBody(emitted.bytes) };
}

// Open a poll. A `ban` poll must name the post under review via `targetEh`; option 0
// is the ban option by convention (matching the engine's own e2e test). The returned
// body carries the display descriptor alongside the record so recipients can label
// the options — see `encodePollBody`.
export function composePersonaPoll(
  descriptor: PersonaPollDescriptor,
  targetEh?: string
): { eh: string; body: string; descriptor: PersonaPollDescriptor } | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  try {
    emitted = currentEngine.emitPoll(
      descriptor.question,
      [...descriptor.options],
      descriptor.kind,
      descriptor.kind === 'ban' ? targetEh : undefined
    );
  } catch (error) {
    log.error(`composePersonaPoll: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(undefined));
  return {
    eh: emitted.eh,
    body: encodePollBody(emitted.bytes, descriptor),
    descriptor,
  };
}

// Cast a ballot in the poll named by `pollEh`.
// Cast a ballot in the poll named by `pollEh`.
//
// A ballot is PSEUDONYMOUS, not anonymous: in circuit the voter is
// `H(sk, poll.context())`, and because that derivation takes no nonce a member can
// produce exactly one pseudonym per poll — which is what enforces one vote each. Two
// ballots by the same member in one poll are linkable to each other (by design, that is
// how a double vote is spotted) but not to the account behind them.
//
// The body is VOTE-marked so it rides the phantom, hiding the real Signal sender.
// Without that, the pseudonym would be pointless — the envelope would name the voter.
export function composePersonaVote(
  pollEh: string,
  optionIndex: number
): { eh: string; body: string } | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  let emitted: Emitted;
  try {
    // The poll's envelope hash IS the poll_id: the engine derives
    // `context = poll.context() = Poseidon(eh)` and the voter's pseudonym as
    // `H(sk, context)`, with no nonce. One pseudonym per poll, hence one vote per
    // member. Nothing else needs passing.
    emitted = currentEngine.emitVote(pollEh, optionIndex);
  } catch (error) {
    log.error(`composePersonaVote: emit failed: ${toLogFormat(error)}`);
    return undefined;
  }
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(undefined));
  return { eh: emitted.eh, body: encodeVoteBody(emitted.bytes) };
}

// Absorb the callbacks (revocations) fired since our last scan. Emitting a scan is
// how a member's own view picks up bans that settled while it was running, and how
// the flag propagates to everyone else's replica.
export function composePersonaScan():
  | { eh: string; body: string }
  | undefined {
  const result = emitAndSelfIngest(currentEngine => currentEngine.emitScan());
  return result ? { eh: result.emitted.eh, body: result.body } : undefined;
}

export const BADGE_SLOTS: ReadonlyArray<{ slot: number; name: string }> = [
  { slot: 1, name: 'Faculty' },
  { slot: 2, name: 'Student' },
  { slot: 3, name: 'Industry' },
];

/**
 * Request a badge. Files a ticket an admin can approve; grants nothing by itself.
 *
 * Attributable on purpose — the requester is asking a human to vouch for them, which
 * is not a claim that can be made anonymously.
 */
export function composeBadgeRequest(
  slot: number
): { eh: string; body: string } | undefined {
  // `encodeBadgeBody`, not the default attributable encoding `emitAndSelfIngest`
  // applies. The marker is the only thing the send splice looks at, so the choice of
  // encoder here IS the choice of whether the requester is named on the wire.
  return emitBadgeRecord(engine => engine.emitBadgeRequest(slot));
}

/** Approve a badge request by its envelope hash (admin action). Phantom-routed. */
export function composeBadgeApprove(
  requestEh: string,
  slot: number
): { eh: string; body: string } | undefined {
  return emitBadgeRecord(engine => engine.emitBadgeApprove(requestEh, slot));
}

/**
 * Emit + self-ingest a badge record, carried under the PHANTOM badge marker.
 *
 * Mirrors `emitAndSelfIngest` exactly except for the encoder. Kept as its own helper so
 * the two badge records cannot drift apart: a request that hides its sender and an
 * approval that does not would be worse than either choice made consistently, because
 * the pair would narrow the anonymity set to "whoever the admin replied to".
 */
function emitBadgeRecord(
  produce: (engine: Engine) => Emitted
): { eh: string; body: string } | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  const emitted = produce(currentEngine);
  currentEngine.ingest(emitted.bytes, ingestTimestampFor(undefined));
  return { eh: emitted.eh, body: encodeBadgeBody(emitted.bytes) };
}

/**
 * The badges this member's own zk object contains — the ONLY authority on possession.
 *
 * Empty when the engine is unavailable or the addon predates `getBadges`. That default
 * is the safe one: it under-claims rather than over-claims, so a build that cannot tell
 * sends no badge instead of asserting an unverified one.
 */
export function heldBadges(): ReadonlyArray<string> {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.getBadges !== 'function') {
    return [];
  }
  try {
    return engine.getBadges();
  } catch (error) {
    log.error(`heldBadges failed: ${toLogFormat(error)}`);
    return [];
  }
}

/** Badge requests awaiting approval, read from the replica's own log. */
export function listPendingBadgeRequests(): ReadonlyArray<{
  eh: string;
  slot: number;
}> {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.pendingBadgeRequests !== 'function') {
    return [];
  }
  try {
    return engine.pendingBadgeRequests();
  } catch (error) {
    log.error(`listPendingBadgeRequests failed: ${toLogFormat(error)}`);
    return [];
  }
}

/**
 * Prove we hold `badge`, by name. Undefined if we do not hold it — the proof is simply
 * unsatisfiable, which is the point: a badge label can be typed, a badge proof cannot.
 */
export function composeBadgeProof(badge: string): Uint8Array | undefined {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.emitBadgeProof !== 'function') {
    log.error('composeBadgeProof: addon has no emitBadgeProof binding');
    return undefined;
  }
  try {
    return engine.emitBadgeProof(badge);
  } catch (error) {
    log.error(`composeBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Verify a badge proof and return the badge NAME it proves.
 *
 * Render this, never a label from the message — otherwise a valid Student proof could
 * be displayed as Faculty and the checkmark would be true while the label lied.
 */
export function verifyBadgeProof(proof: Uint8Array): string | undefined {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.verifyBadgeProof !== 'function') {
    return undefined;
  }
  try {
    return engine.verifyBadgeProof(Buffer.from(proof)) ?? undefined;
  } catch (error) {
    log.error(`verifyBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Produce a ZK proof that two of our own pseudonyms share an author.
 *
 * Contexts, not petnames: for an unlimited pseudonym the context IS the nonce the UI
 * already stores, and the claimed pseudonyms are derived from our secret key inside the
 * circuit — so this cannot assert anything about a persona we do not hold.
 *
 * Unlike the other compose helpers this does NOT self-ingest, because an authorship
 * proof is not a record: nothing is folded into the replica, no accept rule applies,
 * and there is no echo to absorb.
 */
export function composePersonaAuthorship(
  contextA: number,
  contextB: number
): { body: string; proof: Uint8Array } | undefined {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.emitAuthorship !== 'function') {
    log.error('composePersonaAuthorship: addon has no emitAuthorship binding');
    return undefined;
  }
  try {
    const proof = engine.emitAuthorship(contextA, contextB);
    // Both: `body` for the wire, `proof` so the caller can verify its own output
    // before sending and render from the verifier rather than from its own inputs.
    return { body: encodeAuthorshipProof(proof), proof };
  } catch (error) {
    log.error(`composePersonaAuthorship failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Prove possession of `badge` in zero knowledge.
 *
 * Unsatisfiable if this member's object does not actually hold it, which is the whole
 * value of this over the decorative label: a label is a string anyone can type, a proof
 * only exists if an admin approved the badge and the member scanned it in.
 *
 * Not a record, so it does not self-ingest — nothing is folded into the replica and no
 * accept rule applies. Same shape as `composePersonaAuthorship`.
 */
export function composePersonaBadgeProof(
  badge: string
): { body: string; proof: Uint8Array } | undefined {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.emitBadgeProof !== 'function') {
    log.error('composePersonaBadgeProof: addon has no emitBadgeProof binding');
    return undefined;
  }
  try {
    const proof = engine.emitBadgeProof(badge);
    return { body: encodeBadgeProof(proof), proof };
  } catch (error) {
    // Includes the expected case: we do not hold the badge, so the witness does not
    // exist. Logged rather than thrown — the caller turns it into a visible reason.
    log.error(`composePersonaBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Verify a badge proof and return the badge NAME it proves.
 *
 * The name comes from the proof's public inputs via the addon's own lookup, never from
 * the message. A proof that verifies but maps to no known badge value returns undefined
 * rather than a plausible-looking guess.
 */
export function verifyPersonaBadgeProof(
  proof: Uint8Array
): string | undefined {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.verifyBadgeProof !== 'function') {
    return undefined;
  }
  try {
    return engine.verifyBadgeProof(Buffer.from(proof)) ?? undefined;
  } catch (error) {
    log.error(`verifyPersonaBadgeProof failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

/**
 * Verify an authorship proof and return the names it PROVES about.
 *
 * The names come from the proof's own public inputs, never from the message. That is
 * the whole point: a sender holding a valid proof about two pseudonyms they own could
 * otherwise display it beside someone else's persona names, and the checkmark would be
 * true while the statement was false.
 */
export function verifyPersonaAuthorship(
  proof: Uint8Array
): { first: string; second: string } | undefined {
  const engine = getPersonasEngine();
  if (!engine || typeof engine.verifyAuthorship !== 'function') {
    return undefined;
  }
  try {
    return engine.verifyAuthorship(Buffer.from(proof)) ?? undefined;
  } catch (error) {
    log.error(`verifyPersonaAuthorship failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// The engine's own status line for a poll, if it publishes one we can match. Used as
// the poll bubble's status text so the tally shown is the ENGINE's, never something
// the UI derived on its own. Matched defensively (the line format is the engine's to
// choose) and simply absent when no line matches.
// Called from a REDUX SELECTOR (getPropsForMessage), which means it runs synchronously
// on the renderer's main thread, potentially on every store update, once per poll
// message on screen. Two consequences, both learned the hard way:
//
//  1. It must NEVER construct the engine. `getPersonasEngine()` builds lazily, and
//     construction reads the ~51 MB key bundle (and GENERATES it, taking minutes, if the
//     cache is cold). Doing that inside a selector blocks the first paint, so the window
//     opens and then sits blank — with no error, because nothing threw. An instance whose
//     history contains a persona poll hits this; one whose history does not, does not,
//     which is why some instances looked fine and others hung.
//  2. `renderPolls()` is a native call that walks the replica. Calling it per render per
//     poll is wasteful even once the engine is warm, so the result is memoised for a
//     short window — long enough to collapse a burst of renders, short enough that a
//     moving tally still updates promptly.
const POLL_STATUS_TTL_MS = 500;
let pollStatusCache: { atMs: number; lines: ReadonlyArray<string> } | undefined;

export function getPollStatusLine(pollEh: string): string | undefined {
  // Deliberately NOT getPersonasEngine(): peek at what is already built, never build.
  if (!engine) {
    return undefined;
  }
  try {
    const now = Date.now();
    if (!pollStatusCache || now - pollStatusCache.atMs > POLL_STATUS_TTL_MS) {
      pollStatusCache = { atMs: now, lines: engine.renderPolls() };
    }
    const shortEh = pollEh.slice(0, 12);
    return pollStatusCache.lines.find(
      line => line.includes(pollEh) || line.includes(shortEh)
    );
  } catch (error) {
    log.error(`getPollStatusLine failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// Whether the post named by `eh` is currently flagged (its author's persona was
// revoked). The receive path stamps `personaFlagged` at ingest time, but a ban that
// settles LATER has to be re-read from the engine — this is what the flag refresher
// polls. Returns undefined when the engine has no entry for `eh`.
export function isPostFlagged(eh: string): boolean | undefined {
  const currentEngine = getPersonasEngine();
  if (!currentEngine) {
    return undefined;
  }
  try {
    return currentEngine.logEntry(eh)?.flagged;
  } catch (error) {
    log.error(`isPostFlagged failed: ${toLogFormat(error)}`);
    return undefined;
  }
}
