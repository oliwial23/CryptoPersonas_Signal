//! Admin-signed bans (server-backed deployment).
//!
//! A ban invokes the callback the offending post committed to, and it also rotates the
//! Privacy Pass issuer key so tickets the member already holds stop working. Both are
//! things only a group admin may cause (admins are trusted; the server is not). So a ban
//! request carries the admin's Ed25519 signature over [`ban_message`]: the ticket being
//! banned and the epoch the ban is made in. The server refuses an unsigned ban, and it
//! records the signature in the public key-rotation log, where every client checks it
//! against the admin key it pinned (`personas_client`'s rotation check).
//!
//! The admin key is configured out of band: the server reads its public half from
//! `PERSONAS_ADMIN_PK`, an admin's client reads the secret half from the file named by
//! `PERSONAS_ADMIN_KEY_FILE`, and members either set `PERSONAS_ADMIN_PK` too or pin the
//! key the server publishes the first time they see one.

use ark_serialize::{CanonicalSerialize, Compress};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// The group admin's public key.
pub type AdminPk = VerifyingKey;

/// Separates ban signatures from anything else the admin key might sign.
const BAN_DOMAIN: &[u8] = b"personas/ban/v1";

/// The bytes an admin signs to ban the holder of `ticket_hex` in `epoch`.
pub fn ban_message(ticket_hex: &str, epoch: u64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BAN_DOMAIN.len() + 8 + ticket_hex.len());
    msg.extend_from_slice(BAN_DOMAIN);
    msg.extend_from_slice(&epoch.to_le_bytes());
    msg.extend_from_slice(ticket_hex.as_bytes());
    msg
}

/// A callback ticket as the rotation log names it: hex of its canonical uncompressed bytes.
pub fn ticket_hex<T: CanonicalSerialize>(ticket: &T) -> Result<String, String> {
    let mut bytes = Vec::new();
    ticket
        .serialize_with_mode(&mut bytes, Compress::No)
        .map_err(|e| format!("could not encode the ticket: {e}"))?;
    Ok(hex::encode(bytes))
}

/// Parse an admin public key from hex.
pub fn parse_admin_pk(hex_pk: &str) -> Result<VerifyingKey, String> {
    let bytes: [u8; 32] = hex::decode(hex_pk.trim())
        .map_err(|e| format!("the admin public key is not hex: {e}"))?
        .try_into()
        .map_err(|_| "the admin public key is not 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| format!("not an Ed25519 public key: {e}"))
}

/// Parse an admin secret key from hex.
pub fn parse_admin_sk(hex_sk: &str) -> Result<SigningKey, String> {
    let bytes: [u8; 32] = hex::decode(hex_sk.trim())
        .map_err(|_| "the admin secret key is not hex".to_string())?
        .try_into()
        .map_err(|_| "the admin secret key is not 32 bytes".to_string())?;
    Ok(SigningKey::from_bytes(&bytes))
}

/// A fresh admin key pair, as hex: `(secret, public)`.
pub fn generate_admin_key() -> (String, String) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    (hex::encode(sk.to_bytes()), hex::encode(sk.verifying_key().to_bytes()))
}

/// The admin's signature on a ban of `ticket_hex` in `epoch`, as hex.
pub fn sign_ban(sk: &SigningKey, ticket_hex: &str, epoch: u64) -> String {
    hex::encode(sk.sign(&ban_message(ticket_hex, epoch)).to_bytes())
}

/// Check `signature_hex` is the admin's signature on a ban of `ticket_hex` in `epoch`.
pub fn verify_ban(
    admin_pk: &VerifyingKey,
    ticket_hex: &str,
    epoch: u64,
    signature_hex: &str,
) -> Result<(), String> {
    let bytes: [u8; 64] = hex::decode(signature_hex.trim())
        .map_err(|_| "the ban signature is not hex".to_string())?
        .try_into()
        .map_err(|_| "the ban signature is not 64 bytes".to_string())?;
    admin_pk
        .verify_strict(&ban_message(ticket_hex, epoch), &Signature::from_bytes(&bytes))
        .map_err(|_| "the ban is not signed by the group admin".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ban_signature_binds_the_ticket_and_the_epoch() {
        let (sk_hex, pk_hex) = generate_admin_key();
        let sk = parse_admin_sk(&sk_hex).unwrap();
        let pk = parse_admin_pk(&pk_hex).unwrap();
        let sig = sign_ban(&sk, "aa", 7);
        verify_ban(&pk, "aa", 7, &sig).unwrap();
        assert!(verify_ban(&pk, "ab", 7, &sig).is_err(), "another ticket");
        assert!(verify_ban(&pk, "aa", 8, &sig).is_err(), "another epoch");
        let (_, other) = generate_admin_key();
        assert!(verify_ban(&parse_admin_pk(&other).unwrap(), "aa", 7, &sig).is_err());
        assert!(verify_ban(&pk, "aa", 7, "zz").is_err());
    }
}
