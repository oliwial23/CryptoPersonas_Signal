//! Carriage: how a serverless record rides a chat message (workstream **d4**).
//!
//! `SERVERLESS_PROTOCOL.md` §3 says a record *is* a chat message. The d3 engine
//! speaks in record **bytes** (the CBOR envelope `personas_bulletin::replica::record`
//! produces); a [`Transport`](transport_api::Transport) speaks in
//! [`Outgoing`]/[`Incoming`] chat messages with a text body and optional
//! attachments. This module is the thin, reversible bridge between the two, and
//! nothing else in the messenger needs to know how a record is packed.
//!
//! # Inline vs. attachment
//!
//! Record bytes are binary, but most transports carry a text body, so a record is
//! base64'd behind a short **marker** the receiver recognises. Small records — every
//! serverless default, since `FoldScan` is off (§13) — ride inline in the body. A
//! record larger than [`INLINE_LIMIT`] (in practice only a folded Nova scan) would
//! overflow a message body, so it rides as an **attachment** and the body carries
//! only a pointer to it. The attachment path is wired but, with folding off, unused
//! on the demo path.
//!
//! # Why a marker, not "every message is a record"
//!
//! A serverless group is still a real chat: humans (and, under real Signal, the
//! messenger's own control traffic) send ordinary messages that are *not* records.
//! The marker lets [`decode`] cleanly separate protocol records from chatter —
//! a body without the marker is [`None`], ignored by the accept rule, never
//! mis-fed to `Replica::ingest` as a malformed record.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use transport_api::{Attachment, Incoming, Outgoing};

/// Prefixes an **inline** record body: `PZR2:<base64>`. The `2` is the serverless
/// protocol version (`record::SERVERLESS_VERSION`), so a future wire break is
/// visible in the marker itself, not only inside the CBOR.
pub const INLINE_MARKER: &str = "PZR2:";

/// Prefixes a body whose record rides as an **attachment**: `PZR2A:<filename>`.
/// The receiver pulls the named attachment rather than decoding the body.
pub const ATTACH_MARKER: &str = "PZR2A:";

/// The content type stamped on a record attachment.
pub const ATTACH_CONTENT_TYPE: &str = "application/vnd.personas.record";

/// Records at or below this many bytes ride inline; larger ones become an
/// attachment (§3's ~32 KB threshold). Only `FoldScan` exceeds it, and folding is
/// off by default, so on the demo path everything is inline.
pub const INLINE_LIMIT: usize = 32 * 1024;

/// A record packed for a transport: a message body, and any attachment it points to.
///
/// The body is always set (the marker is what the receiver keys on); `attachment`
/// is `Some` only for the over-limit attachment path.
#[derive(Clone, Debug)]
pub struct Carried {
    pub body: String,
    pub attachment: Option<Attachment>,
}

impl Carried {
    /// Fold this into an [`Outgoing`] for `conversation`, preserving `persona`
    /// (the petname a transport shows in the sender slot; `None` for an anonymous
    /// or non-attributed record).
    pub fn into_outgoing(
        self,
        conversation: transport_api::ConversationId,
        persona: Option<String>,
    ) -> Outgoing {
        let mut out = Outgoing::new(conversation, self.body);
        out.persona = persona;
        if let Some(a) = self.attachment {
            out.attachments.push(a);
        }
        out
    }
}

/// Pack record bytes for carriage: inline if small, attachment if large.
pub fn encode(record: &[u8]) -> Carried {
    if record.len() <= INLINE_LIMIT {
        Carried {
            body: format!("{INLINE_MARKER}{}", B64.encode(record)),
            attachment: None,
        }
    } else {
        // Name the attachment by a short digest of its own bytes, so the body's
        // pointer is stable and collision-resistant without carrying the whole hash.
        let filename = format!("record-{}.bin", short_tag(record));
        Carried {
            body: format!("{ATTACH_MARKER}{filename}"),
            attachment: Some(Attachment {
                filename,
                content_type: ATTACH_CONTENT_TYPE.to_string(),
                bytes: record.to_vec(),
            }),
        }
    }
}

/// Recover record bytes from a delivered message body plus its attachments, or
/// `None` if the body is not a record (ordinary chatter, or a pointer to an
/// attachment that did not arrive).
pub fn decode(body: &str, attachments: &[Attachment]) -> Option<Vec<u8>> {
    if let Some(b64) = body.strip_prefix(INLINE_MARKER) {
        // A record whose base64 is corrupt is not a record — a peer cannot make us
        // panic by sending garbage behind the marker.
        return B64.decode(b64.trim()).ok();
    }
    if let Some(name) = body.strip_prefix(ATTACH_MARKER) {
        let name = name.trim();
        return attachments
            .iter()
            .find(|a| a.filename == name)
            .map(|a| a.bytes.clone());
    }
    None
}

/// Convenience: pull a record out of an [`Incoming`] event, or `None` for anything
/// that is not a record-bearing message (a reaction, a feedback button, chatter).
pub fn decode_incoming(incoming: &Incoming) -> Option<Vec<u8>> {
    match incoming {
        Incoming::Message {
            body, attachments, ..
        } => decode(body, attachments),
        _ => None,
    }
}

/// The service-assigned receive timestamp (ms) an [`Incoming`] carries, or `0` for a
/// non-message event. This is the shared clock the d5 barrier cadence buckets by
/// (§4/§14) — see [`Heartbeat`](crate::Heartbeat).
pub fn received_at(incoming: &Incoming) -> u64 {
    match incoming {
        Incoming::Message { received_at, .. } => *received_at,
        _ => 0,
    }
}

/// A short hex tag of some bytes, for naming an attachment.
fn short_tag(bytes: &[u8]) -> String {
    use blake2::{Blake2s256, Digest};
    let mut h = Blake2s256::new();
    h.update(bytes);
    let d: [u8; 32] = h.finalize().into();
    hex_lower(&d[..8])
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport_api::{ConversationId, MessageId};

    #[test]
    fn small_records_ride_inline_and_round_trip() {
        let record = b"a small serverless record".to_vec();
        let carried = encode(&record);
        assert!(carried.body.starts_with(INLINE_MARKER));
        assert!(carried.attachment.is_none());
        assert_eq!(decode(&carried.body, &[]).as_deref(), Some(&record[..]));
    }

    #[test]
    fn large_records_ride_as_an_attachment() {
        let record = vec![7u8; INLINE_LIMIT + 1];
        let carried = encode(&record);
        assert!(carried.body.starts_with(ATTACH_MARKER));
        let attachment = carried.attachment.clone().expect("attachment");
        assert_eq!(attachment.content_type, ATTACH_CONTENT_TYPE);
        // The body points at the attachment; decoding needs it present.
        assert_eq!(
            decode(&carried.body, &[]),
            None,
            "pointer with no attachment"
        );
        assert_eq!(
            decode(&carried.body, std::slice::from_ref(&attachment)).as_deref(),
            Some(&record[..]),
        );
    }

    #[test]
    fn chatter_is_not_a_record() {
        assert_eq!(decode("just saying hi", &[]), None);
        assert_eq!(decode("", &[]), None);
        // A corrupt payload behind the marker decodes to nothing, not a panic.
        assert_eq!(
            decode(&format!("{INLINE_MARKER}!!!not base64!!!"), &[]),
            None
        );
    }

    #[test]
    fn decode_incoming_ignores_non_messages() {
        let react = Incoming::Reaction {
            conversation: ConversationId("room".into()),
            target: MessageId("1".into()),
            emoji: "👍".into(),
            sender: "someone".into(),
        };
        assert_eq!(decode_incoming(&react), None);
    }
}
