// Phase 5 bring-up gate (libsignal level, no server, no GUI).
//
// Property under test: a valid recipient — even an instrumented/malicious member —
// must not be able to tell WHICH member sent a message. We prove that two distinct
// members (alice, bob) can each send a group message that a third member (carol)
// receives as ONE indistinguishable phantom sender: same sender UUID, same device,
// same identity key, byte-identical sender certificate. The only intended
// attribution is the persona (the ZK proof), which lives in the plaintext.
//
// The load-bearing realization (confirmed from the libsignal types):
//   A SenderCertificate binds a `senderKey` (public identity key). sealedSenderEncrypt
//   authenticates the outer envelope with the corresponding PRIVATE identity key and
//   the recipient checks the static key against the cert. So to be byte-identical,
//   every member must SHARE three secrets:
//     (1) the phantom identity keypair (private + public, = the cert's key),
//     (2) the phantom SenderCertificate (signed by the server trust root),
//     (3) the advancing SenderKeyRecord state under a shared distributionId.
//   Sharing (1)+(2) makes the sealed-sender auth indistinguishable; (3) makes the
//   inner group message decrypt against one receiving chain.

import * as sig from '../node_modules/@signalapp/libsignal-client/dist/index.js';

const {
  IdentityKeyPair,
  PublicKey,
  ProtocolAddress,
  ServerCertificate,
  SenderCertificate,
  SenderKeyRecord,
  SenderKeyDistributionMessage,
  processSenderKeyDistributionMessage,
  groupEncrypt,
  groupDecrypt,
  UnidentifiedSenderMessageContent,
  sealedSenderEncrypt,
  sealedSenderDecryptToUsmc,
  SenderKeyStore,
  IdentityKeyStore,
} = sig;

// A fixed "now" so the run is deterministic (Date.now() is fine here in a plain script).
const NOW = 1_700_000_000_000;
const EXPIRES = NOW + 365 * 24 * 3600 * 1000;

// ---- in-memory stores ------------------------------------------------------

class MemSenderKeyStore extends SenderKeyStore {
  constructor() {
    super();
    this.map = new Map();
  }
  _k(sender, distId) {
    return `${sender.name()}::${sender.deviceId()}::${distId}`;
  }
  async saveSenderKey(sender, distId, record) {
    this.map.set(this._k(sender, distId), record.serialize());
  }
  async getSenderKey(sender, distId) {
    const b = this.map.get(this._k(sender, distId));
    return b ? SenderKeyRecord.deserialize(b) : null;
  }
  // Snapshot/restore the raw serialized state — models the shared, on-disk sender
  // key that members coordinate through the roster dir.
  snapshot(sender, distId) {
    return this.map.get(this._k(sender, distId));
  }
  restore(sender, distId, bytes) {
    this.map.set(this._k(sender, distId), bytes);
  }
}

class MemIdentityStore extends IdentityKeyStore {
  constructor(idKeyPair, registrationId) {
    super();
    this.idKeyPair = idKeyPair;
    this.registrationId = registrationId;
    this.known = new Map();
  }
  async getIdentityKey() {
    return this.idKeyPair.privateKey;
  }
  async getLocalRegistrationId() {
    return this.registrationId;
  }
  async saveIdentity(name, key) {
    this.known.set(name.name(), key.serialize());
    return 0;
  }
  async isTrustedIdentity() {
    return true;
  }
  async getIdentity(name) {
    const b = this.known.get(name.name());
    return b ? PublicKey.deserialize(b) : null;
  }
  learn(address, publicKey) {
    this.known.set(address.name(), publicKey.serialize());
  }
}

// ---- test harness ----------------------------------------------------------

function assert(cond, msg) {
  if (!cond) {
    throw new Error(`ASSERT FAILED: ${msg}`);
  }
}

const hex = u8 => Buffer.from(u8).toString('hex');
const enc = new TextEncoder();
const dec = new TextDecoder();

async function main() {
  // --- the REAL test server's UD trust root (what config.serverTrustRoots holds
  //     today; the phantom cert is NOT signed by this one) ---
  const realServerTrustRoot = IdentityKeyPair.generate();

  // --- our phantom trust root: we mint it, and ADD its public key to
  //     config.serverTrustRoots. Desktop's receive path validates with
  //     validateWithTrustRoots(serverTrustRoots, time), which passes iff ANY
  //     listed root signed the cert — so real traffic still validates against
  //     the real root, and phantom traffic validates against ours. ---
  const phantomTrustRoot = IdentityKeyPair.generate();
  const serverKey = IdentityKeyPair.generate();
  const serverCert = ServerCertificate.new(
    1,
    serverKey.publicKey,
    phantomTrustRoot.privateKey
  );
  // This is exactly what MessageReceiver passes to validateWithTrustRoots.
  const configuredTrustRoots = [
    realServerTrustRoot.publicKey,
    phantomTrustRoot.publicKey,
  ];

  // --- the SHARED phantom identity + its sender certificate (secrets 1 & 2) ---
  const phantomAci = '11111111-1111-4111-8111-111111111111';
  const phantomIdentity = IdentityKeyPair.generate();
  const phantomRegId = 4242;
  const phantomCert = SenderCertificate.new(
    phantomAci,
    null,
    1, // device id
    phantomIdentity.publicKey,
    EXPIRES,
    serverCert,
    serverKey.privateKey
  );
  const phantomAddress = ProtocolAddress.new(phantomAci, 1);

  // --- the shared group sender key (secret 3), minted once and distributed ---
  const distributionId = '22222222-2222-4222-8222-222222222222';
  const generatorStore = new MemSenderKeyStore();
  const skdm = await SenderKeyDistributionMessage.create(
    phantomAddress,
    distributionId,
    generatorStore
  );
  const skdmBytes = skdm.serialize();

  // The shared, advancing sender-key state. In the real demo this lives in the
  // roster dir and each sender loads/mutates/saves it (serial posting). Here one
  // store instance stands in for that shared state.
  const sharedSenderStore = generatorStore;

  // --- the three members. alice & bob SEND; carol RECEIVES. ---
  const members = {};
  for (const [name, aci] of [
    ['alice', '33333333-3333-4333-8333-333333333333'],
    ['bob', '44444444-4444-4444-8444-444444444444'],
    ['carol', '55555555-5555-4555-8555-555555555555'],
  ]) {
    members[name] = {
      aci,
      address: ProtocolAddress.new(aci, 1),
      identity: new MemIdentityStore(IdentityKeyPair.generate(), 5000 + Object.keys(members).length),
      senderKeys: new MemSenderKeyStore(),
    };
  }
  const { alice, bob, carol } = members;

  // carol installs the shared receiving chain (she processed the SKDM out-of-band).
  await processSenderKeyDistributionMessage(
    phantomAddress,
    SenderKeyDistributionMessage.deserialize(skdmBytes),
    carol.senderKeys
  );

  // Everyone learns carol's identity public key (from a prior identified round trip
  // in the real path; seeded here). Needed for the sealed-sender outer layer.
  // Each sender authenticates the outer layer with the SHARED phantom identity.
  function phantomStoreFor(senderRegId) {
    const s = new MemIdentityStore(phantomIdentity, senderRegId);
    s.learn(carol.address, carol.identity.idKeyPair.publicKey);
    return s;
  }

  // Send as phantom: encrypt under the shared sender key, wrap in the phantom cert,
  // seal to carol using the shared phantom identity.
  async function sendAsPhantom(senderRegId, plaintext) {
    const ciphertext = await groupEncrypt(
      phantomAddress,
      distributionId,
      sharedSenderStore, // advances the shared chain
      enc.encode(plaintext)
    );
    const usmc = UnidentifiedSenderMessageContent.new(
      ciphertext,
      phantomCert,
      0, // content hint: default
      null // no group id
    );
    const envelope = await sealedSenderEncrypt(
      usmc,
      carol.address,
      phantomStoreFor(senderRegId)
    );
    return envelope;
  }

  // What carol can OBSERVE about a received message's sender.
  async function carolObserve(envelope) {
    const usmc = await sealedSenderDecryptToUsmc(envelope, carol.identity);
    const cert = usmc.senderCertificate();
    // Exactly Desktop's receive-side check: validateWithTrustRoots over the
    // configured list (real root + phantom root).
    const validAgainstTrustRoot = cert.validateWithTrustRoots(
      configuredTrustRoots,
      NOW
    );
    const senderAddr = ProtocolAddress.new(
      cert.senderUuid(),
      cert.senderDeviceId()
    );
    const plaintextBytes = await groupDecrypt(
      senderAddr,
      carol.senderKeys,
      usmc.contents()
    );
    return {
      senderUuid: cert.senderUuid(),
      senderDeviceId: cert.senderDeviceId(),
      senderKeyHex: hex(cert.key().serialize()),
      certBytesHex: hex(cert.serialize()),
      validAgainstTrustRoot,
      plaintext: dec.decode(plaintextBytes),
    };
  }

  // === serial posting: alice then bob, both under the shared chain ===
  const env1 = await sendAsPhantom(alice.identity.registrationId, 'hello from a persona (msg #1)');
  const env2 = await sendAsPhantom(bob.identity.registrationId, 'second post (msg #2)');

  const obs1 = await carolObserve(env1);
  const obs2 = await carolObserve(env2);

  console.log('\n=== what carol observes ===');
  console.log('msg #1 (sent by alice):', {
    senderUuid: obs1.senderUuid,
    senderDeviceId: obs1.senderDeviceId,
    valid: obs1.validAgainstTrustRoot,
    plaintext: obs1.plaintext,
  });
  console.log('msg #2 (sent by bob):  ', {
    senderUuid: obs2.senderUuid,
    senderDeviceId: obs2.senderDeviceId,
    valid: obs2.validAgainstTrustRoot,
    plaintext: obs2.plaintext,
  });

  // --- the anonymity assertions ---
  assert(obs1.plaintext.includes('#1'), 'msg1 decrypts to alice content');
  assert(obs2.plaintext.includes('#2'), 'msg2 decrypts to bob content');
  assert(obs1.validAgainstTrustRoot, 'msg1 cert validates against trust root');
  assert(obs2.validAgainstTrustRoot, 'msg2 cert validates against trust root');

  assert(obs1.senderUuid === phantomAci, 'msg1 sender is the phantom');
  assert(obs2.senderUuid === phantomAci, 'msg2 sender is the phantom');
  assert(obs1.senderUuid === obs2.senderUuid, 'both messages share the sender uuid');
  assert(obs1.senderDeviceId === obs2.senderDeviceId, 'both share the device id');
  assert(obs1.senderKeyHex === obs2.senderKeyHex, 'both share the identity key');
  assert(obs1.certBytesHex === obs2.certBytesHex, 'the sender certificate is BYTE-IDENTICAL across senders');

  // Prove it's the ADDED phantom root (not the real one) that admits the cert:
  // the phantom cert must FAIL against the real root alone and PASS against ours.
  const usmcForRootCheck = await sealedSenderDecryptToUsmc(env1, carol.identity);
  const certForRootCheck = usmcForRootCheck.senderCertificate();
  assert(
    !certForRootCheck.validateWithTrustRoots([realServerTrustRoot.publicKey], NOW),
    'phantom cert must NOT validate against the real trust root alone'
  );
  assert(
    certForRootCheck.validateWithTrustRoots([phantomTrustRoot.publicKey], NOW),
    'phantom cert must validate against the phantom trust root'
  );
  console.log('\n✅ trust-root config: phantom cert admitted only by the added phantom root,');
  console.log('   real Signal traffic still validated by the real root (both in the list).');

  console.log('\n✅ recipient-anonymity: alice and bob are indistinguishable to carol.');
  console.log('   - sender uuid identical:', obs1.senderUuid === obs2.senderUuid);
  console.log('   - device id identical:  ', obs1.senderDeviceId === obs2.senderDeviceId);
  console.log('   - identity key identical:', obs1.senderKeyHex === obs2.senderKeyHex);
  console.log('   - cert bytes identical: ', obs1.certBytesHex === obs2.certBytesHex);

  // === negative test: a member who does NOT share the phantom identity cannot
  //     forge a message under the phantom cert (the cert key won't match). ===
  let forgedRejected = false;
  try {
    const ciphertext = await groupEncrypt(
      phantomAddress,
      distributionId,
      sharedSenderStore,
      enc.encode('forged')
    );
    const usmc = UnidentifiedSenderMessageContent.new(ciphertext, phantomCert, 0, null);
    // alice tries to seal with her REAL identity instead of the shared phantom one.
    const aliceRealStore = new MemIdentityStore(alice.identity.idKeyPair, alice.identity.registrationId);
    aliceRealStore.learn(carol.address, carol.identity.idKeyPair.publicKey);
    const forgedEnv = await sealedSenderEncrypt(usmc, carol.address, aliceRealStore);
    // carol should reject: the static key won't match the cert key.
    await sealedSenderDecryptToUsmc(forgedEnv, carol.identity);
  } catch (e) {
    forgedRejected = true;
    console.log('\n✅ forgery rejected (real identity != phantom cert key):', String(e.message || e).split('\n')[0]);
  }
  assert(forgedRejected, 'sealed sender must bind the cert key to the sending identity');

  console.log('\n=== GATE PASSED ===');
}

main().catch(e => {
  console.error('\n❌ GATE FAILED');
  console.error(e);
  process.exit(1);
});
