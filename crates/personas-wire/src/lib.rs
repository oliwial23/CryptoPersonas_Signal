//! The byte format. Every proof, record, and callback that crosses a process boundary is
//! encoded here and nowhere else.
//!
//! Before this crate, `serialize_with_mode(&mut bytes, Compress::No)` appeared in ~60 places
//! across the client and the server, and the two agreed only by convention. Each route
//! defined its own implicit format — "an `ExecutedMethod`, then a `Vec<F>` of public
//! inputs, uncompressed, no header" — which is fine until a record has to survive a version
//! skew, or be read by a member who does not know which route it came from. In serverless
//! mode nobody does: a record arrives as a message in a group chat, and the reader has to
//! work out what it is from the bytes alone.
//!
//! So a record is an [`Envelope`]: a CBOR header naming a version and a [`Kind`], wrapped
//! around an arkworks-serialized payload.
//!
//! # Compressed payloads, uncompressed parameters
//!
//! Records are serialized with [`Compress::Yes`]. A record is small (hundreds of bytes to a
//! few KB), it is stored forever in the bulletin, and in serverless mode *every member*
//! downloads it — so halving it is worth the handful of point decompressions it costs to
//! read.
//!
//! Proving keys and bulletin dumps are not records and do not come through here. They are
//! tens to hundreds of megabytes of curve points, the client refetches them on every
//! invocation, and they travel over localhost. Compressing them would add a modular square
//! root per point to every client start — the `bench/*.py` harness alone spawns the client
//! hundreds of times — to save bandwidth that costs nothing. [`raw`] is where that decision
//! is written down, so the two conventions cannot be confused for an oversight.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use serde::{Deserialize, Serialize};

/// Bumped when the meaning of any [`Kind`]'s payload changes. A reader that sees a version
/// it does not know refuses the record rather than misreading it.
pub const VERSION: u16 = 1;

/// Records are compressed; see the module docs.
const RECORD_COMPRESS: Compress = Compress::Yes;

/// What a payload is.
///
/// The route a record arrived on used to be its only type tag, which works exactly as long
/// as records arrive on routes. Serverless records arrive as chat messages, so the tag has
/// to be in the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A member joining: a commitment to their new object.
    Join,
    /// A post, anonymous: `ExecutedMethod<_, _, _, _, 1>`.
    Post,
    /// A post under a pseudonym: `ExecutedMethod`, then `Vec<F>` = `[context, claimed]`.
    PostPseudo,
    /// A rate-limited pseudonymous post: `ExecutedMethod`, then `[context, claimed, i]`.
    PostPseudoRate,
    /// A request for a badge: `ExecutedMethod`, then `[index, claimed]`.
    BadgeRequest,
    /// A standalone Groth16 proof and its public inputs: `Proof`, then `Vec<F>`.
    ///
    /// One kind for four predicates — a pseudonym, a vote, an authorship claim, a badge
    /// claim — because the payload *shape* is identical and it is the verifying key, chosen
    /// by the verifier, that decides which statement was proved. A record cannot talk its
    /// way into being checked against the wrong key by relabelling itself.
    Predicate,
    /// A callback scan: `ExecutedMethod<_, _, _, _, 0>`.
    Scan,
    /// A Nova-folded scan: `FoldingProofData`. Megabyte-scale — see the plan's note on why
    /// this is off by default in serverless.
    FoldScan,
    /// A callback commitment: `CallbackCom`.
    Callback,
}

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("not a personas record: {0}")]
    Malformed(String),

    #[error("record is version {found}, this build speaks version {VERSION}")]
    Version { found: u16 },

    #[error("expected a {expected:?} record, got a {found:?}")]
    Kind { expected: Kind, found: Kind },

    #[error("{kind:?} payload is corrupt: {source}")]
    Payload {
        kind: Kind,
        source: ark_serialize::SerializationError,
    },

    #[error("could not serialize a {kind:?} record: {source}")]
    Serialize {
        kind: Kind,
        source: ark_serialize::SerializationError,
    },
}

pub type Result<T> = std::result::Result<T, WireError>;

/// A versioned, self-describing record.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    v: u16,
    kind: Kind,
    /// `serde_bytes` so CBOR writes one byte string, not an array of 400 integers.
    #[serde(with = "serde_bytes")]
    payload: Vec<u8>,
}

/// Builds a record's payload, item by item, in the order the reader will pull them.
///
/// Several payloads are more than one value — a proof and then its public inputs — which the
/// old code expressed by writing both into the same `Vec<u8>` and trusting the reader to
/// know. It still is a concatenation; the difference is that [`Kind`] now says which one.
pub struct Payload {
    kind: Kind,
    bytes: Vec<u8>,
}

impl Payload {
    pub fn new(kind: Kind) -> Self {
        Self {
            kind,
            bytes: Vec::new(),
        }
    }

    pub fn push<T: CanonicalSerialize>(&mut self, value: &T) -> Result<&mut Self> {
        value
            .serialize_with_mode(&mut self.bytes, RECORD_COMPRESS)
            .map_err(|source| WireError::Serialize {
                kind: self.kind,
                source,
            })?;
        Ok(self)
    }
}

/// Reads a payload back, item by item.
///
/// Owns its bytes: CBOR gives us the payload as an owned `Vec` and the values inside it are
/// pulled out one after another, so the reader carries a cursor over that buffer rather than
/// borrowing from an envelope the caller would then have to keep alive.
pub struct Reader {
    kind: Kind,
    cursor: std::io::Cursor<Vec<u8>>,
}

impl Reader {
    /// The next value in the payload.
    ///
    /// `Validate::Yes` — a record is adversarial input. It arrives from a member who may
    /// want a point off the curve or outside the prime-order subgroup to end up inside a
    /// circuit, and the cost of checking is negligible against the proof verification that
    /// follows. (The *parameter* path validates nothing, because a proving key comes from
    /// the server the client already trusts to have generated it.)
    pub fn pull<T: CanonicalDeserialize>(&mut self) -> Result<T> {
        T::deserialize_with_mode(&mut self.cursor, RECORD_COMPRESS, Validate::Yes).map_err(
            |source| WireError::Payload {
                kind: self.kind,
                source,
            },
        )
    }

    /// True once every value has been pulled. A payload with bytes left over is a payload
    /// the reader misunderstood.
    pub fn is_empty(&self) -> bool {
        self.cursor.position() as usize >= self.cursor.get_ref().len()
    }
}

/// Wrap a payload in a versioned envelope.
pub fn encode(payload: Payload) -> Result<Vec<u8>> {
    let envelope = Envelope {
        v: VERSION,
        kind: payload.kind,
        payload: payload.bytes,
    };

    let mut out = Vec::new();
    ciborium::into_writer(&envelope, &mut out)
        .map_err(|e| WireError::Malformed(format!("could not write envelope: {e}")))?;
    Ok(out)
}

/// One value, one record — the common case.
pub fn encode_one<T: CanonicalSerialize>(kind: Kind, value: &T) -> Result<Vec<u8>> {
    let mut payload = Payload::new(kind);
    payload.push(value)?;
    encode(payload)
}

/// Open a record, insisting it is the kind the caller expected.
///
/// The kind check is not ceremony. Every payload here is a sequence of field elements and
/// curve points, so a `Scan` fed to a `Post` reader will *often deserialize* — into
/// garbage, which then fails proof verification with an error that says nothing about what
/// actually went wrong. Rejecting on the tag turns that into one clear line.
pub fn decode(expected: Kind, bytes: &[u8]) -> Result<Reader> {
    let envelope: Envelope = ciborium::from_reader(bytes)
        .map_err(|e| WireError::Malformed(format!("could not read envelope: {e}")))?;

    if envelope.v != VERSION {
        return Err(WireError::Version { found: envelope.v });
    }
    if envelope.kind != expected {
        return Err(WireError::Kind {
            expected,
            found: envelope.kind,
        });
    }

    Ok(Reader {
        kind: envelope.kind,
        cursor: std::io::Cursor::new(envelope.payload),
    })
}

/// What kind of record this is, without committing to reading it.
pub fn peek(bytes: &[u8]) -> Result<Kind> {
    let envelope: Envelope = ciborium::from_reader(bytes)
        .map_err(|e| WireError::Malformed(format!("could not read envelope: {e}")))?;
    Ok(envelope.kind)
}

/// Bulk artifacts: proving keys, bulletin dumps. Not records — no envelope, no compression.
///
/// See the module docs. In short: these are megabytes of curve points that the client
/// refetches every run over localhost, and compressing them trades a free resource
/// (bandwidth to 127.0.0.1) for an expensive one (a square root per point, on every start).
pub mod raw {
    use super::*;

    pub const COMPRESS: Compress = Compress::No;

    pub fn encode<T: CanonicalSerialize>(value: &T) -> std::result::Result<Vec<u8>, ark_serialize::SerializationError> {
        let mut bytes = Vec::new();
        value.serialize_with_mode(&mut bytes, COMPRESS)?;
        Ok(bytes)
    }

    /// `Validate::No`: the only producer is the server whose keys these are, and validating
    /// a proving key means a subgroup check on every one of its millions of points.
    pub fn decode<T: CanonicalDeserialize>(
        bytes: &[u8],
    ) -> std::result::Result<T, ark_serialize::SerializationError> {
        T::deserialize_with_mode(bytes, COMPRESS, Validate::No)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_std::{UniformRand, rand::SeedableRng};

    fn field_elements(n: usize) -> Vec<Fr> {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        (0..n).map(|_| Fr::rand(&mut rng)).collect()
    }

    #[test]
    fn a_record_round_trips() {
        let inputs = field_elements(3);
        let bytes = encode_one(Kind::Predicate, &inputs).unwrap();

        let mut reader = decode(Kind::Predicate, &bytes).unwrap();
        let back: Vec<Fr> = reader.pull().unwrap();

        assert_eq!(back, inputs);
        assert!(reader.is_empty(), "the payload held exactly one value");
    }

    #[test]
    fn multi_value_payloads_round_trip_in_order() {
        let proof = field_elements(2);
        let pub_inputs = field_elements(3);

        let mut payload = Payload::new(Kind::PostPseudo);
        payload.push(&proof).unwrap().push(&pub_inputs).unwrap();
        let bytes = encode(payload).unwrap();

        let mut reader = decode(Kind::PostPseudo, &bytes).unwrap();
        assert_eq!(reader.pull::<Vec<Fr>>().unwrap(), proof);
        assert_eq!(reader.pull::<Vec<Fr>>().unwrap(), pub_inputs);
        assert!(reader.is_empty());
    }

    /// The failure this crate exists to make impossible: two records whose payloads are both
    /// "a sequence of field elements" cannot be silently confused for one another.
    #[test]
    fn a_record_of_the_wrong_kind_is_refused_not_misread() {
        let bytes = encode_one(Kind::Scan, &field_elements(3)).unwrap();

        match decode(Kind::Post, &bytes) {
            Err(WireError::Kind { expected, found }) => {
                assert_eq!(expected, Kind::Post);
                assert_eq!(found, Kind::Scan);
            }
            other => panic!("expected a kind mismatch, got {other:?}"),
        }
    }

    #[test]
    fn the_kind_can_be_read_without_decoding() {
        let bytes = encode_one(Kind::FoldScan, &field_elements(1)).unwrap();
        assert_eq!(peek(&bytes).unwrap(), Kind::FoldScan);
    }

    #[test]
    fn garbage_is_not_a_record() {
        assert!(matches!(
            decode(Kind::Post, b"not cbor at all"),
            Err(WireError::Malformed(_))
        ));
    }

    /// What compression actually buys, and on what.
    ///
    /// It halves *curve points* — a compressed G1 is its x-coordinate plus a sign bit, and
    /// the y is recovered with a square root. A Groth16 proof is 2×G1 + 1×G2, so a proof
    /// nearly halves. This is the saving that matters: in serverless mode every member
    /// downloads every record.
    #[test]
    fn curve_points_halve() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let points: Vec<ark_bn254::G1Affine> =
            (0..16).map(|_| ark_bn254::G1Affine::rand(&mut rng)).collect();

        let record = encode_one(Kind::Predicate, &points).unwrap();
        let uncompressed = raw::encode(&points).unwrap();

        assert!(
            record.len() < uncompressed.len() * 2 / 3,
            "record {} bytes vs raw {} bytes — compression is not happening",
            record.len(),
            uncompressed.len()
        );
    }

    /// And what it does not buy. Field elements are already minimal, so a payload of nothing
    /// but public inputs pays the envelope's ~15 bytes for no saving at all. That is a fine
    /// trade for knowing what a record *is*, but it should not be mistaken for compression.
    #[test]
    fn field_elements_do_not_compress() {
        let inputs = field_elements(64);
        let record = encode_one(Kind::Predicate, &inputs).unwrap();
        let uncompressed = raw::encode(&inputs).unwrap();

        assert!(record.len() > uncompressed.len());
        assert!(
            record.len() - uncompressed.len() < 32,
            "the envelope should cost a header, not a multiple"
        );
    }
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("kind", &self.kind)
            .field("consumed", &self.cursor.position())
            .finish()
    }
}
