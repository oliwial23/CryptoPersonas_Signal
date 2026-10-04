// Phase 5 bring-up gate II — the MULTI-RECIPIENT send path (the actual Desktop API).
//
// The single-recipient gate proved the anonymity property with sealedSenderEncrypt.
// But Desktop's group send uses sealedSenderMultiRecipientEncrypt(content, recipients,
// identityStore, sessionStore), which takes recipient identities from SESSIONS and the
// LOCAL sender identity from the identityStore. The phantom splice hinges on one fact:
//
//   The passed identityStore's key pair (the PHANTOM identity) — not the real local
//   identity embedded in the session — drives the sealed-sender AUTH, so a recipient
//   decrypting with the phantom CERT's key succeeds, and every member is byte-identical.
//
// We prove it by running the real multi-recipient encrypt with a phantom identity store
// over a REAL session (built via processPreKeyBundle), extracting the recipient's slice
// with sealedSenderMultiRecipientMessageForSingleRecipient, and decrypting. Plus a
// negative: encrypting the phantom cert under the REAL identity must be REJECTED on
// decrypt (proving the identity store, not the session, is the auth key — and that the
// cert key is bound to the sending identity).

import * as sig from '../node_modules/@signalapp/libsignal-client/dist/index.js';

const {
  IdentityKeyPair,
  PrivateKey,
  PublicKey,
  KEMKeyPair,
  ProtocolAddress,
  PreKeyBundle,
  processPreKeyBundle,
  ServerCertificate,
  SenderCertificate,
  SenderKeyRecord,
  SenderKeyDistributionMessage,
  processSenderKeyDistributionMessage,
  groupEncrypt,
  groupDecrypt,
  UnidentifiedSenderMessageContent,
  sealedSenderMultiRecipientEncrypt,
  sealedSenderMultiRecipientMessageForSingleRecipient,
  sealedSenderDecryptToUsmc,
  SenderKeyStore,
  IdentityKeyStore,
  SessionStore,
} = sig;

const NOW = 1_700_000_000_000;
const EXPIRES = NOW + 365 * 24 * 3600 * 1000;
const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = u8 => Buffer.from(u8).toString('hex');
function assert(c, m) { if (!c) throw new Error(`ASSERT FAILED: ${m}`); }

// ---- in-memory stores ------------------------------------------------------
class MemSenderKeyStore extends SenderKeyStore {
  map = new Map();
  _k(s, d) { return `${s.name()}::${s.deviceId()}::${d}`; }
  async saveSenderKey(s, d, r) { this.map.set(this._k(s, d), r.serialize()); }
  async getSenderKey(s, d) { const b = this.map.get(this._k(s, d)); return b ? SenderKeyRecord.deserialize(b) : null; }
}
class MemIdentityStore extends IdentityKeyStore {
  known = new Map();
  constructor(idKeyPair, regId) { super(); this.idKeyPair = idKeyPair; this.regId = regId; }
  async getIdentityKey() { return this.idKeyPair.privateKey; }
  async getLocalRegistrationId() { return this.regId; }
  async saveIdentity(name, key) { this.known.set(name.name(), key.serialize()); return 0; }
  async isTrustedIdentity() { return true; }
  async getIdentity(name) { const b = this.known.get(name.name()); return b ? PublicKey.deserialize(b) : null; }
}
class MemSessionStore extends SessionStore {
  map = new Map();
  async saveSession(name, record) { this.map.set(name.name() + '::' + name.deviceId(), record.serialize()); }
  async getSession(name) {
    const b = this.map.get(name.name() + '::' + name.deviceId());
    return b ? sig.SessionRecord.deserialize(b) : null;
  }
  async getExistingSessions(addrs) {
    return addrs.map(a => {
      const b = this.map.get(a.name() + '::' + a.deviceId());
      if (!b) throw new Error('no session for ' + a.name());
      return sig.SessionRecord.deserialize(b);
    });
  }
}

// Build a recipient's prekey bundle and register a session for `senderName` -> recipient.
async function establishSession(senderSessionStore, senderIdentityStore, senderAddr, recip) {
  const spkId = 77;
  const spkPriv = PrivateKey.generate();
  const spkSig = recip.identity.idKeyPair.privateKey.sign(spkPriv.getPublicKey().serialize());
  const kyberId = 88;
  const kyber = KEMKeyPair.generate();
  const kyberSig = recip.identity.idKeyPair.privateKey.sign(kyber.getPublicKey().serialize());
  const preId = 99;
  const prePriv = PrivateKey.generate();

  const bundle = PreKeyBundle.new(
    recip.regId,
    recip.address.deviceId(),
    preId,
    prePriv.getPublicKey(),
    spkId,
    spkPriv.getPublicKey(),
    spkSig,
    recip.identity.idKeyPair.publicKey,
    kyberId,
    kyber.getPublicKey(),
    kyberSig
  );
  await processPreKeyBundle(
    bundle,
    recip.address,
    senderAddr,
    senderSessionStore,
    senderIdentityStore,
    new Date(NOW)
  );
}

async function main() {
  // Phantom trust root (added to config.serverTrustRoots) + a server cert under it.
  const phantomTrustRoot = IdentityKeyPair.generate();
  const serverKey = IdentityKeyPair.generate();
  const serverCert = ServerCertificate.new(1, serverKey.publicKey, phantomTrustRoot.privateKey);

  // Shared phantom identity + cert (secrets 1 & 2).
  const phantomAci = '11111111-1111-4111-8111-111111111111';
  const phantomIdentity = IdentityKeyPair.generate();
  const phantomAddress = ProtocolAddress.new(phantomAci, 1);
  const phantomCert = SenderCertificate.new(
    phantomAci, null, 1, phantomIdentity.publicKey, EXPIRES, serverCert, serverKey.privateKey
  );

  // Shared advancing group sender key (secret 3).
  const distributionId = '22222222-2222-4222-8222-222222222222';
  const sharedSenderStore = new MemSenderKeyStore();
  const skdm = await SenderKeyDistributionMessage.create(phantomAddress, distributionId, sharedSenderStore);
  const skdmBytes = skdm.serialize();

  // Members: alice & bob SEND (each their own real account/session), carol RECEIVES.
  const mk = (aci, regId) => ({ aci, regId, address: ProtocolAddress.new(aci, 1), identity: new MemIdentityStore(IdentityKeyPair.generate(), regId) });
  const alice = mk('33333333-3333-4333-8333-333333333333', 5001);
  const bob = mk('44444444-4444-4444-8444-444444444444', 5002);
  const carol = mk('55555555-5555-4555-8555-555555555555', 5003);

  // carol installs the shared receive chain (SKDM processed out-of-band at boot).
  carol.senderKeys = new MemSenderKeyStore();
  await processSenderKeyDistributionMessage(
    phantomAddress, SenderKeyDistributionMessage.deserialize(skdmBytes), carol.senderKeys
  );

  // alice & bob each build a REAL session with carol (their own real identity + store).
  alice.sessions = new MemSessionStore();
  bob.sessions = new MemSessionStore();
  await establishSession(alice.sessions, alice.identity, alice.address, carol);
  await establishSession(bob.sessions, bob.identity, bob.address, carol);

  // The phantom identity store used for the sealed-sender LOCAL identity, seeded with
  // the recipient identities (as Desktop's real DB identity store already knows them).
  const phantomIdentityStore = () => {
    const s = new MemIdentityStore(phantomIdentity, 4242);
    s.known.set(carol.address.name(), carol.identity.idKeyPair.publicKey.serialize());
    return s;
  };

  // Send-as-phantom over the REAL multi-recipient API: real session store (recipient
  // info), phantom identity store (sender auth), phantom cert + shared sender key.
  async function sendAsPhantomMulti(sender, plaintext) {
    const ciphertext = await groupEncrypt(phantomAddress, distributionId, sharedSenderStore, enc.encode(plaintext));
    const content = UnidentifiedSenderMessageContent.new(ciphertext, phantomCert, 0, null);
    const blob = await sealedSenderMultiRecipientEncrypt(
      content, [carol.address], phantomIdentityStore(), sender.sessions
    );
    // The server fans out; extract carol's single-recipient slice.
    return sealedSenderMultiRecipientMessageForSingleRecipient(blob);
  }

  async function carolObserve(recvMsg) {
    const usmc = await sealedSenderDecryptToUsmc(recvMsg, carol.identity);
    const cert = usmc.senderCertificate();
    const senderAddr = ProtocolAddress.new(cert.senderUuid(), cert.senderDeviceId());
    const pt = await groupDecrypt(senderAddr, carol.senderKeys, usmc.contents());
    return {
      senderUuid: cert.senderUuid(),
      senderDeviceId: cert.senderDeviceId(),
      certBytesHex: hex(cert.serialize()),
      valid: cert.validateWithTrustRoots([phantomTrustRoot.publicKey], NOW),
      plaintext: dec.decode(pt),
    };
  }

  const m1 = await sendAsPhantomMulti(alice, 'multi msg #1 from alice');
  const m2 = await sendAsPhantomMulti(bob, 'multi msg #2 from bob');
  const o1 = await carolObserve(m1);
  const o2 = await carolObserve(m2);

  console.log('=== multi-recipient observations ===');
  console.log('msg#1 (alice):', { uuid: o1.senderUuid, dev: o1.senderDeviceId, valid: o1.valid, pt: o1.plaintext });
  console.log('msg#2 (bob):  ', { uuid: o2.senderUuid, dev: o2.senderDeviceId, valid: o2.valid, pt: o2.plaintext });

  assert(o1.plaintext.includes('#1'), 'msg1 decrypts');
  assert(o2.plaintext.includes('#2'), 'msg2 decrypts');
  assert(o1.valid && o2.valid, 'both certs validate against phantom trust root');
  assert(o1.senderUuid === phantomAci && o2.senderUuid === phantomAci, 'both sent as phantom');
  assert(o1.senderUuid === o2.senderUuid, 'same sender uuid');
  assert(o1.senderDeviceId === o2.senderDeviceId, 'same device id');
  assert(o1.certBytesHex === o2.certBytesHex, 'BYTE-IDENTICAL cert across alice & bob (multi-recipient path)');
  console.log('\n✅ multi-recipient: phantom identity store drives auth; alice & bob indistinguishable to carol.');

  // Negative: sending the phantom cert but authenticating with alice's REAL identity
  // must be REJECTED on decrypt (proves the identityStore — not the session — is the
  // sender-auth key, and the cert key is bound to it).
  let rejected = false;
  try {
    const ciphertext = await groupEncrypt(phantomAddress, distributionId, sharedSenderStore, enc.encode('forged'));
    const content = UnidentifiedSenderMessageContent.new(ciphertext, phantomCert, 0, null);
    // alice.identity has her REAL key pair as the local identity — mismatched to phantom cert.
    alice.identity.known.set(carol.address.name(), carol.identity.idKeyPair.publicKey.serialize());
    const blob = await sealedSenderMultiRecipientEncrypt(content, [carol.address], alice.identity, alice.sessions);
    const recvMsg = sealedSenderMultiRecipientMessageForSingleRecipient(blob);
    await sealedSenderDecryptToUsmc(recvMsg, carol.identity);
  } catch (e) {
    rejected = true;
    console.log('✅ forgery rejected (real identity != phantom cert key):', String(e.message || e).split('\n')[0]);
  }
  assert(rejected, 'multi-recipient sealed sender must bind cert key to the identity-store key');

  console.log('\n=== MULTI-RECIPIENT GATE PASSED ===');
}

main().catch(e => { console.error('\n❌ GATE FAILED\n', e); process.exit(1); });
