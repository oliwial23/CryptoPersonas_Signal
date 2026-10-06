// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the pure carriage convention — how a CryptoPersonas record is
// packed into an ordinary message body. No native/engine dependency, so the send
// path can import the marker without pulling in the addon.
//
// Mirrors personas-messenger carriage.rs `INLINE_MARKER`: a record body is
// `PZR2:<base64>`. A body without a marker is ordinary chatter.
//
// SIX markers. The split follows what the ENGINE already does: any record whose
// in-circuit identity is a pseudonym must also hide its Signal sender, or the envelope
// re-identifies what the proof went to trouble to anonymise.
//   - POSTS (`PZP2:`) ride the shared phantom identity.
//   - POLLS (`PZQ2:`) ride the phantom, so the poll's CREATOR is anonymous, and carry a
//     DISPLAY descriptor (question + option labels) so a recipient can draw the bubble.
//   - BALLOTS (`PZV2:`) ride the phantom. In-circuit the voter is
//     `H(sk, poll.context())` with no nonce — one pseudonym per poll, hence one vote
//     per member — so voting is PSEUDONYMOUS, not anonymous.
//   - RATINGS (`PZE2:`) ride the phantom for the same reason: `member.rate` uses
//     `context = target.context()`, giving one rating per member per target.
//   - JOIN / SCAN (`PZR2:`) are sent ATTRIBUTABLY under the real account. Joins
//     especially MUST be: the anti-Sybil / ban-evasion guarantee depends on one
//     membership per real account, which an anonymous join would defeat.
//   - TOPIC ANNOUNCEMENTS (`PZT2:`) are not ZK records at all — coordination metadata
//     mapping a topic name to its random context. The engine never sees them.
// The record-bearing markers all yield the same CBOR bytes on decode (the engine
// classifies kind); the marker steers SEND-side routing and carries display metadata.

export const PERSONAS_MARKER = 'PZR2:';
export const PERSONAS_POST_MARKER = 'PZP2:';
export const PERSONAS_POLL_MARKER = 'PZQ2:';
export const PERSONAS_VOTE_MARKER = 'PZV2:';
// Ratings are pseudonymous in-circuit (member.rate uses context = target.context(),
// exactly like a vote), so they must ride the phantom too — otherwise the Signal
// envelope names the rater and the in-circuit pseudonym is pointless.
export const PERSONAS_RATE_MARKER = 'PZE2:';
// Topic announcements are NOT ZK records — see decodeTopicAnnouncement.
export const PERSONAS_TOPIC_MARKER = 'PZT2:';

// An AUTHORSHIP CLAIM: "these two personas are the same person". Like the topic
// announcement (PZT2) this is NOT a ZK record — it carries no proof, the engine never
// sees it, and it is decoded separately so it is never handed to `ingest`.
//
// The real thing is a proof. `authorship_pred` exists in personas-core and its Merkle
// proving key already ships, but the serverless `Member` has no method to build the
// statement, so there is nothing to verify against here. See PERSONAS_SERVERLESS_TODO.md
// section 1 — this marker is exactly what that work would replace.
export const PERSONAS_AUTHORSHIP_MARKER = 'PZU2:';

// Records that must ride the shared phantom identity, i.e. whose AUTHOR must be
// unlinkable: posts, polls, ballots and ratings. Everything else is attributable.
const PHANTOM_MARKERS = [
  PERSONAS_POST_MARKER,
  PERSONAS_POLL_MARKER,
  PERSONAS_VOTE_MARKER,
  PERSONAS_RATE_MARKER,
] as const;

const ALL_MARKERS = [
  PERSONAS_MARKER,
  PERSONAS_POST_MARKER,
  PERSONAS_POLL_MARKER,
  PERSONAS_VOTE_MARKER,
  PERSONAS_RATE_MARKER,
] as const;

// How to attribute a composed post. Pure type (no engine dependency) so the
// composer UI can reference it without importing the native addon.
export type PersonaChoice =
  // An UNLIMITED plain pseudonym. Takes no topic: a member may mint as many of these
  // as they like, so each one carries a fresh random `nonce` to derive a new petname.
  | { kind: 'pseudo'; nonce: number }
  // One of the RATE-LIMITED personas, which ARE topic-scoped:
  //   persona = H(sk || context || index),  index < MAX_PSEUDO
  // `context` is the topic's random context number (see personasTopics), so the same
  // member has unlinkable petnames across topics, and at most MAX_PSEUDO identities
  // within any one topic.
  | { kind: 'rate'; context: number; index: number }
  // No linkable persona at all.
  | { kind: 'anon' };

// The rate-limit bound. MUST match `personas_core::circuits::MAX_PSEUDO`, which is
// 4 — offering more slots than the circuit accepts produces a proof that every replica
// rejects, and offering fewer just hides capacity.
//
// Note the circuit's check is `i != MAX_PSEUDO` (circuits.rs x9), not `i < MAX_PSEUDO`,
// so it only excludes exactly 4 — i = 5 would pass. The UI never offers out-of-range
// slots, but the bound is weaker in-circuit than the paper's `assert(i < k)`.
export const MAX_PSEUDO = 4;

// Wrap raw record bytes for carriage as a message body. Default marker is the
// ATTRIBUTABLE one (join / scan); posts, polls, ballots and ratings have their own.
export function encodeRecordBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_MARKER + Buffer.from(bytes).toString('base64');
}

// Wrap a POST record — the one kind that rides the shared phantom identity.
//
// Two shapes behind the same marker, and the plain one is unchanged from before badges
// existed so old and new bodies interoperate:
//
//   PZP2:<base64 record>                     — no badge claim (the common case)
//   PZP2:<base64 {"r":"<record>","b":"..."}> — with a badge claim
//
// The badge is DISPLAY METADATA, exactly like a poll's option labels: untrusted, not
// part of the proof, and not checked by anything. See personasBadges.std.ts — a peer can
// claim any badge it likes. It is carried here rather than in the record because the
// record is the engine's and the engine has no notion of badges in the serverless model.
export function encodePostBody(
  bytes: Buffer | Uint8Array,
  badge?: string,
  contextName?: string
): string {
  const record = Buffer.from(bytes).toString('base64');
  if (!badge && !contextName) {
    return PERSONAS_POST_MARKER + record;
  }
  // `c` is the CONTEXT NAME, display metadata exactly like the badge and a poll's option
  // labels. The record already carries the context NUMBER in its public inputs, so the
  // number is authoritative and provable; the human-readable name is not, and a peer
  // could mislabel its own post's context. That is a display-integrity limit, not a
  // soundness one — the rate-limit still binds to the number inside the proof.
  //
  // Carried rather than resolved locally because a recipient may not have heard the
  // context announcement (PZT2) yet, and a post that renders with no context at all is
  // worse than one that renders with an unverified name.
  const envelope = { r: record, b: badge, c: contextName };
  return (
    PERSONAS_POST_MARKER +
    Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64')
  );
}

// The badge claim carried by a PZP2 body, if any. Undefined for a plain post, for a
// non-post, and for anything malformed — a badge is never worth failing a message over.
export function decodePostBadge(
  body: string | undefined | null
): string | undefined {
  if (!body?.startsWith(PERSONAS_POST_MARKER)) {
    return undefined;
  }
  const envelope = parsePostEnvelope(body);
  return typeof envelope?.b === 'string' ? envelope.b : undefined;
}

// The context NAME a post was made under, if it carried one. Undefined for an anonymous
// or context-free pseudonymous post. Untrusted — see encodePostBody.
export function decodePostContextName(
  body: string | undefined | null
): string | undefined {
  if (!body?.startsWith(PERSONAS_POST_MARKER)) {
    return undefined;
  }
  const envelope = parsePostEnvelope(body);
  return typeof envelope?.c === 'string' ? envelope.c : undefined;
}

// A post body is an envelope only if its base64 decodes to JSON with an `r` field.
// A plain post's payload is raw record bytes, which will not parse as JSON — so this
// distinguishes the two shapes without a second marker and without a version bump.
function parsePostEnvelope(
  body: string
): { r: string; b?: string; c?: string } | undefined {
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_POST_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as {
      r?: unknown;
      b?: unknown;
      c?: unknown;
    };
    if (typeof parsed?.r !== 'string') {
      return undefined;
    }
    return {
      r: parsed.r,
      b: typeof parsed.b === 'string' ? parsed.b : undefined,
      c: typeof parsed.c === 'string' ? parsed.c : undefined,
    };
  } catch {
    // Not JSON: a plain post. Expected, not exceptional.
    return undefined;
  }
}

// The DISPLAY metadata for a poll: what to draw in the bubble. The ZK record is the
// authority for everything that matters — who may vote, whether a ballot is
// well-formed, when the poll closes, and whether a ban settles are all decided by the
// engine from the record. This descriptor only supplies the human-readable strings the
// engine does not hand back, so a recipient can label the options it votes on.
//
// Treat it as UNTRUSTED: a peer could mislabel its own poll's options. That is a
// display-integrity limit of the demo, not a soundness one — a mislabelled option
// still resolves to the same option INDEX inside the proof, so the tally and any
// resulting ban are exactly what the ZK system says they are.
export type PersonaPollDescriptor = {
  question: string;
  options: ReadonlyArray<string>;
  kind: 'ban' | 'standard';
};

// NOTE on poll_id. An earlier version of this carried a client-drawn random `pollId`,
// on the assumption the voter's pseudonym was PRF(sk, poll_id) for a server-issued
// poll_id. The engine does not work that way and never reads such a field:
//
//   member.vote()  ->  context = poll.context()  =  Poseidon(eh)
//                      claimed = pseudonym(sk, context) = H(sk, context)
//
// The poll's ENVELOPE HASH is the poll_id. record.rs says so explicitly — the context
// is "unpredictable until the record exists (which is what stops a member pre-computing
// a pseudonym), and unique per record", and it "replaces the service's fresh_context()".
// So the eh-derived context is the deliberate substitute for a server-drawn random id,
// and it has the same one-pseudonym-per-poll property because the derivation takes no
// nonce. Carrying an extra random number would be dead weight that nothing enforces.

// The wire shape behind PZQ2: the record plus the display descriptor.
type PollEnvelope = {
  // base64 record bytes
  r: string;
  q: string;
  o: ReadonlyArray<string>;
  k: 'ban' | 'standard';
};

// Wrap a POLL record together with its display descriptor.
export function encodePollBody(
  bytes: Buffer | Uint8Array,
  descriptor: PersonaPollDescriptor
): string {
  const envelope: PollEnvelope = {
    r: Buffer.from(bytes).toString('base64'),
    q: descriptor.question,
    o: [...descriptor.options],
    k: descriptor.kind,
  };
  return (
    PERSONAS_POLL_MARKER +
    Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64')
  );
}

function parsePollEnvelope(body: string): PollEnvelope | undefined {
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_POLL_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as PollEnvelope;
    if (
      typeof parsed?.r !== 'string' ||
      typeof parsed?.q !== 'string' ||
      !Array.isArray(parsed?.o)
    ) {
      return undefined;
    }
    return parsed;
  } catch {
    return undefined;
  }
}

// The poll display descriptor behind a PZQ2 body, or undefined for anything else.
export function decodePollDescriptor(
  body: string | undefined | null
): PersonaPollDescriptor | undefined {
  if (!body?.startsWith(PERSONAS_POLL_MARKER)) {
    return undefined;
  }
  const envelope = parsePollEnvelope(body);
  if (!envelope) {
    return undefined;
  }
  return {
    question: envelope.q,
    options: envelope.o.map(String),
    kind: envelope.k === 'ban' ? 'ban' : 'standard',
  };
}

// The raw record bytes behind a body's marker (any of the three), or undefined for
// ordinary chatter. Kind (post vs join vs …) is the engine's job, not the marker's.
export function decodeRecordBody(
  body: string | undefined | null
): Buffer | undefined {
  if (!body) {
    return undefined;
  }
  const marker = ALL_MARKERS.find(m => body.startsWith(m));
  if (!marker) {
    return undefined;
  }
  try {
    if (marker === PERSONAS_POLL_MARKER) {
      const envelope = parsePollEnvelope(body);
      return envelope ? Buffer.from(envelope.r, 'base64') : undefined;
    }
    if (marker === PERSONAS_POST_MARKER) {
      // A post is EITHER raw record bytes or a {r, b} envelope (see encodePostBody).
      // Unwrap when it is an envelope; otherwise fall through to the plain path. Getting
      // this wrong would hand the engine JSON instead of a record, so every badged post
      // would be rejected — which is why the envelope shape is detected by parse success
      // rather than assumed.
      const envelope = parsePostEnvelope(body);
      if (envelope) {
        return Buffer.from(envelope.r, 'base64');
      }
    }
    return Buffer.from(body.slice(marker.length), 'base64');
  } catch {
    return undefined;
  }
}

// Does this body carry a record whose AUTHOR must be unlinkable — i.e. one that MUST
// ride the shared phantom identity? Used by the group send splice to decide routing.
//
// Posts, polls and ballots all qualify. A poll's creator and a voter are as entitled to
// anonymity as a poster: an attributable ballot would defeat the entire point of an
// anonymous poll, and an attributable poll would expose who called for a revocation.
//
// Joins, ratings and scans deliberately do NOT: the anti-Sybil accounting rests on one
// membership per real account, which an anonymous join would defeat.
export function isPersonaPhantomBody(body: string | undefined | null): boolean {
  if (!body) {
    return false;
  }
  return PHANTOM_MARKERS.some(m => body.startsWith(m));
}

// A topic announcement: `{name, context}` telling every member which context number to
// use for a named topic. NOT a ZK record — it carries no proof and the engine never
// sees it. It is pure coordination metadata, the stand-in for the personas server's
// topic registry, so it is decoded separately and never handed to `ingest`.
export type PersonaTopicAnnouncement = {
  name: string;
  context: number;
};

export function encodeTopicAnnouncement(
  announcement: PersonaTopicAnnouncement
): string {
  return (
    PERSONAS_TOPIC_MARKER +
    Buffer.from(JSON.stringify(announcement), 'utf8').toString('base64')
  );
}

export function decodeTopicAnnouncement(
  body: string | undefined | null
): PersonaTopicAnnouncement | undefined {
  if (!body?.startsWith(PERSONAS_TOPIC_MARKER)) {
    return undefined;
  }
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_TOPIC_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as PersonaTopicAnnouncement;
    if (typeof parsed?.name !== 'string' || !Number.isFinite(parsed?.context)) {
      return undefined;
    }
    return { name: parsed.name, context: parsed.context };
  } catch {
    return undefined;
  }
}

// Wrap a VOTE record. Separate from the generic marker because a ballot rides the
// phantom (see isPersonaPhantomBody) while joins/ratings/scans do not.
// An authorship claim: "these two personas are both me". UNVERIFIED — see the marker
// comment. Sent ATTRIBUTABLY on purpose: the claimant is voluntarily linking two of
// their own personas, so there is nothing left to hide about who is speaking, and
// routing it over the phantom would falsely suggest the link itself is protected.
export type PersonaAuthorshipClaim = {
  /** The two persona petnames being linked. */
  first: string;
  second: string;
};

export function encodeAuthorshipClaim(claim: PersonaAuthorshipClaim): string {
  return (
    PERSONAS_AUTHORSHIP_MARKER +
    Buffer.from(
      JSON.stringify({ a: claim.first, b: claim.second }),
      'utf8'
    ).toString('base64')
  );
}

export function decodeAuthorshipClaim(
  body: string | undefined | null
): PersonaAuthorshipClaim | undefined {
  if (!body?.startsWith(PERSONAS_AUTHORSHIP_MARKER)) {
    return undefined;
  }
  try {
    const json = Buffer.from(
      body.slice(PERSONAS_AUTHORSHIP_MARKER.length),
      'base64'
    ).toString('utf8');
    const parsed = JSON.parse(json) as { a?: unknown; b?: unknown };
    if (typeof parsed?.a !== 'string' || typeof parsed?.b !== 'string') {
      return undefined;
    }
    return { first: parsed.a, second: parsed.b };
  } catch {
    return undefined;
  }
}

export function encodeVoteBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_VOTE_MARKER + Buffer.from(bytes).toString('base64');
}

// Wrap a RATE record. Like a ballot, it rides the phantom.
export function encodeRateBody(bytes: Buffer | Uint8Array): string {
  return PERSONAS_RATE_MARKER + Buffer.from(bytes).toString('base64');
}
