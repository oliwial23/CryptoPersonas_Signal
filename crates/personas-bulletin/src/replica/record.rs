//! The serverless record model and its byte codec (workstream **d3**).
//!
//! In *service* mode a record's type is the HTTP route it arrived on, and its
//! payload is whatever that route's handler expects — an `ExecutedMethod`, then
//! maybe a `Vec<F>` of public inputs, with the message body travelling *beside*
//! the proof in the JSON request. Serverless deletes the routes: a record is a
//! chat message, and the reader has to work out what it is, and reconstruct
//! everything the server used to supply, from the bytes alone. So the body moves
//! *into* the record, and every record names the object root it was built on —
//! the two changes `SERVERLESS_PROTOCOL.md` §3 calls the wire break to version 2.
//!
//! This module is that wire, kept deliberately self-contained rather than folded
//! into [`personas_wire`]: the service server still speaks `personas_wire`
//! version 1, and the serverless record set (new kinds `Rate`/`PollOpen`/`Vote`,
//! new fields `body`/`obj_root`) is only meaningful to the replica engine. When
//! records actually ride Signal (workstream e2) this is where `personas_wire`
//! version 2 gets reconciled.
//!
//! # Shape
//!
//! A [`Record`] is a plain `serde` enum. The arkworks values inside it —
//! `ExecutedMethod`, Groth16 proofs, field elements — are not `serde` types, so
//! each is wrapped in [`Ark`], which serialises through arkworks'
//! `CanonicalSerialize` into a CBOR byte string. The whole thing is CBOR-encoded
//! into an [`Envelope`] carrying a version, and the record is referenced
//! everywhere by its **envelope hash** ([`Eh`]) — the collision-resistant hash of
//! those envelope bytes, never a messenger id (§4: ids are sender-set and
//! non-unique, so any cross-reference keyed on one is forgeable).

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use blake2::{Blake2s256, Digest};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zk_callbacks::generic::object::{Com, Nul};
use zk_callbacks::generic::user::ExecutedMethod;

use personas_core::{Args, Cr, F, Snark};

/// The serverless protocol version. Distinct from [`personas_wire::VERSION`] (1):
/// a reader that sees a version it does not know refuses the record rather than
/// misread a version-1 service payload as a version-2 serverless one.
///
/// 3: a join carries the joining account and a proof that its object is fresh, and a
/// group admin's re-join approval exists. A version-2 record is refused.
pub const SERVERLESS_VERSION: u16 = 3;

/// Records are compressed, matching `personas_wire`'s reasoning: every member
/// downloads every record forever, so halving a proof is worth the point
/// decompressions it costs to read.
const COMPRESS: Compress = Compress::Yes;

/// A member's committed post carries exactly one callback ticket (`NUMCBS = 1`);
/// a scan carries none (`NUMCBS = 0`). Named here so the codec and the engine
/// agree.
pub type PostExec = ExecutedMethod<F, Snark, Args, Cr, 1>;
/// A scan's `ExecutedMethod`: it invokes no new callbacks, so `NUMCBS = 0`.
pub type ScanExec = ExecutedMethod<F, Snark, Args, Cr, 0>;
/// A standalone Groth16 proof (a vote or a rating).
pub type PredProof = <Snark as ark_snark::SNARK<F>>::Proof;

// ---------------------------------------------------------------------------------------
// Eh — the envelope hash
// ---------------------------------------------------------------------------------------

/// The collision-resistant hash of an encoded record.
///
/// Every cross-reference in the protocol — a rating's target, a vote's poll, an
/// admin ban's post — names an `Eh`, because a record's *content* is the only
/// thing about it that cannot be forged or duplicated. It is a byte digest (so it
/// is `Hash`/`Eq` and keys a map cleanly); the field-element a circuit needs (a
/// poll or rating **context**) is derived from it by [`Eh::context`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Eh(pub [u8; 32]);

impl Eh {
    /// The digest of an encoded record.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut h = Blake2s256::new();
        h.update(bytes);
        Eh(h.finalize().into())
    }

    /// The field-element **context** a pseudonym is derived against for this
    /// record: `H(eh)` (`SERVERLESS_PROTOCOL.md` §8 for polls, §10 for ratings).
    ///
    /// Deterministic (every replica computes the same one), unpredictable before
    /// the record exists (which is what stops a member pre-computing a pseudonym),
    /// and unique per record (which keeps pseudonyms in different polls/targets
    /// unlinkable). It replaces the service's `fresh_context()`.
    pub fn context(&self) -> F {
        crate::merkle::tree::poseidon2(&[F::from_le_bytes_mod_order(&self.0)])
    }
}

impl std::fmt::Debug for Eh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Eh({})", hex::encode(&self.0[..6]))
    }
}

impl std::fmt::Display for Eh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ---------------------------------------------------------------------------------------
// Ark<T> — an arkworks value inside a serde document
// ---------------------------------------------------------------------------------------

/// A `CanonicalSerialize` value carried inside a `serde` structure as a CBOR byte
/// string.
///
/// arkworks and serde are two different serialisation worlds; a `Record` needs
/// both (a `serde` enum whose variants hold `ExecutedMethod`s and field
/// elements). Rather than hand-roll every variant, one wrapper bridges them:
/// `serialize` writes the arkworks bytes into `serde_bytes`, `deserialize` reads
/// them back with `Validate::Yes` — a record is adversarial input, so its curve
/// points are checked to be on-curve and in-subgroup before a proof ever touches
/// them.
#[derive(Clone)]
pub struct Ark<T>(pub T);

impl<T> std::fmt::Debug for Ark<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The inner arkworks value is not `Debug`; its identity is its bytes, which
        // the record's `Eh` already captures, so a placeholder is all that is useful.
        f.write_str("Ark(..)")
    }
}

impl<T: CanonicalSerialize> Serialize for Ark<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut bytes = Vec::new();
        self.0
            .serialize_with_mode(&mut bytes, COMPRESS)
            .map_err(serde::ser::Error::custom)?;
        serde_bytes::serialize(&bytes, s)
    }
}

impl<'de, T: CanonicalDeserialize> Deserialize<'de> for Ark<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde_bytes::deserialize(d)?;
        let value = T::deserialize_with_mode(&bytes[..], COMPRESS, Validate::Yes)
            .map_err(D::Error::custom)?;
        Ok(Ark(value))
    }
}

// ---------------------------------------------------------------------------------------
// The record kinds
// ---------------------------------------------------------------------------------------

/// What a post claims about its author — the serverless mirror of the service
/// `Flavour`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Flavour {
    /// Nothing: an unlinkable post by some unbanned member.
    Anon,
    /// A pseudonym, scoped to a member-chosen context.
    Pseudo,
    /// A pseudonym plus an index `i`, holding a member to `RATE_LIMITED_PERSONAS_PER_CONTEXT` (3) pseudonyms
    /// per context.
    PseudoRate,
}

/// Whether a poll merely gauges opinion or, if it carries and passes, revokes a
/// post's author.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PollKind {
    /// An ordinary poll: the tally is rendered, nothing is invoked.
    Standard,
    /// A ban poll: if it closes `yes > no`, the target's ticket is settled with
    /// `BAN_FLAG` at the close barrier (§7).
    Ban,
}

/// A serverless record: one accept-rule input, self-describing from its bytes.
///
/// Every proof-carrying variant names the `obj_root` it was built on, because the
/// verifier has to know which root to pin before it can verify (§5.1) — a member
/// proves against whatever recent root they hold, and the replica accepts only a
/// root it computed itself.
///
/// Not `Clone`: an `ExecutedMethod` holds a Groth16 proof that is neither `Clone`
/// nor `Debug`, and a record is a use-once ingest input anyway. The engine buffers
/// and journals records as *bytes*, never as owned `Record`s.
#[derive(Debug, Serialize, Deserialize)]
pub enum Record {
    /// A member joining: a commitment to their fresh object, plus the initial
    /// nullifier that object consumes. Unlike the service store (which samples the
    /// nullifier randomly on join), serverless carries it as data so every replica
    /// appends an identical leaf — determinism is a hard requirement (§d1).
    ///
    /// PROVEN (version 3): `proof` is a `join_pred` proof with public inputs
    /// `[object, account]` — the committed object is fresh (no badges, reputation, ban
    /// flag, callbacks or scan state; only its secret key and randomness are its own) —
    /// so a member can no longer join with an object of its own making. `account` is the
    /// joining Signal account (`personas_core::account_field` of its ACI); the replica
    /// allows one join per account plus one per admin re-join approval, and the client
    /// refuses a join whose `account` is not the account that sent it.
    Join {
        object: Ark<Com<F>>,
        old_nul: Ark<Nul<F>>,
        account: Ark<F>,
        proof: Ark<PredProof>,
    },

    /// A group admin allows `account` ONE more join (after a reset request). Carries no
    /// proof; the client accepts it only when its sender is a Signal group admin, and
    /// it is sent under the admin's own account so every member can check that.
    RejoinApprove { account: Ark<F> },

    /// A post. `extra` is the flavour's public arguments: empty for `Anon`,
    /// `[context, claimed]` for `Pseudo`, `[context, claimed, i]` for
    /// `PseudoRate`. The context of a plain pseudonym is member-chosen (not a
    /// replica-derived one), so it rides in the proof's public inputs and the
    /// replica pins only `obj_root`.
    Post {
        flavour: Flavour,
        exec: Ark<PostExec>,
        extra: Ark<Vec<F>>,
        body: String,
        obj_root: Ark<F>,
    },

    /// A BADGE REQUEST. An interaction, like a post, so it files a callback — and that
    /// callback is the thing an approver later invokes with a BADGE flag. Without a
    /// ticket there would be nothing to approve.
    ///
    /// CARRIES NO IDENTITY, and does not need to. The grant travels by callback: the
    /// approval names this record's envelope hash, the replica marks the ticket, and the
    /// requester absorbs it at their next scan because only they can. So who sent this
    /// record is irrelevant to whether the badge lands, and the Desktop client
    /// accordingly carries it under the anonymous phantom identity (`PZB2:` in
    /// personasCarriage.std.ts) rather than the real account.
    ///
    /// An earlier version of this comment claimed the request was "attributable by
    /// design" because a human admin must vouch for a person. That describes a different
    /// protocol than the one implemented here — nothing below reads a requester identity.
    /// The consequence is that an admin approves a REQUEST, not a PERSON.
    ///
    /// `slot` is which badge is being asked for (1=Faculty, 2=Student, 3=Industry). It
    /// is DATA, not proof: the request says what you want, the approval decides whether
    /// you get it, and the circuit decides what the flag means.
    BadgeRequest {
        exec: Ark<PostExec>,
        slot: u8,
        obj_root: Ark<F>,
    },

    /// An approval of a badge request, naming the request's envelope hash.
    ///
    /// Carries no proof: it is an admin's say-so, gated client-side on Signal's
    /// group-admin role. Like the request, it is carried anonymously by the Desktop
    /// client — an approval that named its sender while the request did not would narrow
    /// the request's anonymity set to "whoever that admin replied to", so the pair has to
    /// agree. The accept rule only marks the requester's ticket, and
    /// the existing barrier machinery does the rest — invoke with the BADGE flag, then
    /// the requester's own scan writes the badge in-circuit.
    ///
    /// NOT ENFORCED at the protocol level: nothing here checks that the sender is an
    /// admin, so a modified client could approve itself. Closing that needs an admin key
    /// in this accept rule (PERSONAS_ZK_WORKPLAN.md step 3b).
    BadgeApprove {
        target: Eh,
        slot: u8,
    },

    /// A rating of another record. Serverless erases the reacting account, so a
    /// rating must now carry a proof (§10): `pseudonym_pred` under
    /// `context = target.context()`, revealing `claimed`. One rating per
    /// `claimed` per target.
    Rate {
        target: Eh,
        delta: i8,
        proof: Ark<PredProof>,
        claimed: Ark<F>,
        obj_root: Ark<F>,
    },

    /// Announce a poll. Its context is not minted by anyone — it is
    /// `this_record.context()` (§8), so voters can derive their poll pseudonym
    /// only once the poll exists.
    PollOpen {
        question: String,
        options: Vec<String>,
        kind: PollKind,
        /// The post under review, for a `Ban` poll.
        target: Option<Eh>,
    },

    /// A ballot in a poll. Proves `pseudonym_pred` under the poll's context; the
    /// replica records it against `claimed` (one member, one vote) and a later
    /// ballot from the same `claimed` replaces the earlier one.
    Vote {
        poll: Eh,
        option: u32,
        proof: Ark<PredProof>,
        claimed: Ark<F>,
        obj_root: Ark<F>,
    },

    /// A callback scan: the member proves they absorbed every callback invoked on
    /// them since their last scan and skipped none. `cb_memb_root`/`cb_nmemb_root`
    /// name the barrier the scan proves against; the replica pins its *own*
    /// current-barrier roots (§5.2) and rejects a scan built on a superseded one.
    Scan {
        exec: Ark<ScanExec>,
        obj_root: Ark<F>,
        cb_memb_root: Ark<F>,
        cb_nmemb_root: Ark<F>,
    },

    /// A group admin's PERMANENT BAN of the author of post `target`: its callback is
    /// invoked with `BAN_FLAG` at the next barrier, with no poll and nothing anyone can
    /// vote down. Carries no proof; like [`Record::RejoinApprove`] it is sent under the
    /// admin's own account and the client ingests it only from a Signal group admin.
    Ban { target: Eh },
}

impl Record {
    /// The variant name, for logging and the outcome report.
    pub fn kind(&self) -> &'static str {
        match self {
            Record::Join { .. } => "Join",
            Record::Post { .. } => "Post",
            Record::Rate { .. } => "Rate",
            Record::PollOpen { .. } => "PollOpen",
            Record::Vote { .. } => "Vote",
            Record::Scan { .. } => "Scan",
            Record::BadgeRequest { .. } => "BadgeRequest",
            Record::BadgeApprove { .. } => "BadgeApprove",
            Record::RejoinApprove { .. } => "RejoinApprove",
            Record::Ban { .. } => "Ban",
        }
    }
}

// ---------------------------------------------------------------------------------------
// The envelope and its codec
// ---------------------------------------------------------------------------------------

/// The owned form, for decoding.
#[derive(Deserialize)]
struct Envelope {
    v: u16,
    record: Record,
}

/// The borrowed form, for encoding — a `Record` is not `Clone`, so the envelope
/// borrows it rather than taking a copy.
#[derive(Serialize)]
struct EnvelopeRef<'a> {
    v: u16,
    record: &'a Record,
}

/// A record failed to encode or decode.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("could not encode a {kind} record: {source}")]
    Encode {
        kind: &'static str,
        source: ciborium::ser::Error<std::io::Error>,
    },
    #[error("not a serverless record: {0}")]
    Malformed(String),
    #[error("record is serverless version {found}, this build speaks version {SERVERLESS_VERSION}")]
    Version { found: u16 },
}

/// Encode a record and return the bytes together with their [`Eh`].
///
/// The two always travel together: a record's identity *is* the hash of its
/// bytes, so computing it anywhere other than at encode/decode time invites two
/// callers hashing subtly different serialisations.
pub fn encode(record: &Record) -> Result<(Vec<u8>, Eh), CodecError> {
    let envelope = EnvelopeRef {
        v: SERVERLESS_VERSION,
        record,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&envelope, &mut bytes).map_err(|source| CodecError::Encode {
        kind: record.kind(),
        source,
    })?;
    let eh = Eh::of_bytes(&bytes);
    Ok((bytes, eh))
}

/// Decode a record, returning it with the [`Eh`] recomputed from the bytes
/// exactly as read — so a decoded record's identity is what any other replica
/// would compute for the same bytes, not something the sender could assert.
pub fn decode(bytes: &[u8]) -> Result<(Record, Eh), CodecError> {
    let envelope: Envelope = ciborium::from_reader(bytes)
        .map_err(|e| CodecError::Malformed(format!("could not read envelope: {e}")))?;
    if envelope.v != SERVERLESS_VERSION {
        return Err(CodecError::Version { found: envelope.v });
    }
    Ok((envelope.record, Eh::of_bytes(bytes)))
}

/// The record re-encoded WITHOUT its private text — a post's body, a poll's question
/// and option labels (the number of options stays: a vote names one by index) — for
/// handing to a late joiner who should not read the group's past messages.
///
/// The bytes no longer hash to the record's [`Eh`], so whoever stores them must keep
/// the original `Eh` beside them ([`super::Replica::import_records`]). Nothing the
/// replica derives depends on the removed text: no proof covers it, and ratings and
/// polls refer to records by their original `Eh`.
pub fn strip_private_text(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let (mut record, _) = decode(bytes)?;
    match &mut record {
        Record::Post { body, .. } => body.clear(),
        Record::PollOpen {
            question, options, ..
        } => {
            question.clear();
            options.iter_mut().for_each(String::clear);
        }
        _ => {}
    }
    Ok(encode(&record)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn a_join_round_trips_and_its_eh_is_stable() {
        let mut rng = StdRng::seed_from_u64(1);
        let rec = Record::Join {
            object: Ark(F::rand(&mut rng)),
            old_nul: Ark(F::rand(&mut rng)),
            account: Ark(F::rand(&mut rng)),
            proof: Ark(PredProof::default()),
        };
        let (bytes, eh) = encode(&rec).unwrap();
        let (back, eh2) = decode(&bytes).unwrap();
        assert_eq!(eh, eh2, "decode recomputes the same eh");
        match back {
            Record::Join {
                object, old_nul, ..
            } => {
                let Record::Join {
                    object: o0,
                    old_nul: n0,
                    ..
                } = &rec
                else {
                    unreachable!()
                };
                assert_eq!(object.0, o0.0);
                assert_eq!(old_nul.0, n0.0);
            }
            _ => panic!("wrong kind"),
        }
        // Re-encoding is byte-identical, so the eh is a function of content alone.
        let (bytes2, _) = encode(&rec).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn distinct_records_have_distinct_ehs() {
        let a = Record::PollOpen {
            question: "ban?".into(),
            options: vec!["yes".into(), "no".into()],
            kind: PollKind::Ban,
            target: None,
        };
        let b = Record::PollOpen {
            question: "ban!".into(),
            options: vec!["yes".into(), "no".into()],
            kind: PollKind::Ban,
            target: None,
        };
        let (_, ea) = encode(&a).unwrap();
        let (_, eb) = encode(&b).unwrap();
        assert_ne!(ea, eb);
        // And the context each derives is likewise distinct and deterministic.
        assert_ne!(ea.context(), eb.context());
        assert_eq!(ea.context(), ea.context());
    }

    #[test]
    fn a_future_version_is_refused() {
        let rec = Record::PollOpen {
            question: "q".into(),
            options: vec![],
            kind: PollKind::Standard,
            target: None,
        };
        let (bytes, _) = encode(&rec).unwrap();
        // Hand-craft an envelope one version ahead.
        let mut ahead = Vec::new();
        ciborium::into_writer(
            &EnvelopeRef {
                v: SERVERLESS_VERSION + 1,
                record: &rec,
            },
            &mut ahead,
        )
        .unwrap();
        assert!(matches!(
            decode(&ahead),
            Err(CodecError::Version { found }) if found == SERVERLESS_VERSION + 1
        ));
        // The well-formed one still decodes.
        assert!(decode(&bytes).is_ok());
    }

    #[test]
    fn garbage_is_not_a_record() {
        assert!(matches!(decode(b"not cbor"), Err(CodecError::Malformed(_))));
    }
}
