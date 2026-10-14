// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo, Phase 5 — the shared phantom identity that gives recipient-
// anonymity. Every member sends group messages under ONE shared sender
// certificate + ONE shared group sender key, so a recipient (even an
// instrumented member) sees byte-identical Signal sender metadata for everyone;
// the only attribution is the persona carried in the ZK record. Proven at the
// libsignal level in scratchpad/phantom-gate.mjs.
//
// The three shared secrets (see the gate):
//   1. the phantom IDENTITY keypair (it IS the cert's senderKey; sealed-sender
//      auth binds the private key to the cert, so members must share it),
//   2. the phantom SenderCertificate (signed by a trust root we mint and add to
//      config.serverTrustRoots so Desktop's receive-side validateWithTrustRoots
//      admits it),
//   3. the advancing group sender key under a shared distributionId.
//
// This module owns the bundle: generate it once, share it across demo instances
// through the roster dir, and expose the pieces the send splice
// (encryptForSenderKey) and the boot-time receive install need. Delivery rides
// Desktop's real GroupV2 sender-key path — the phantom lives only INSIDE the
// sealed envelope; the real account still authorizes delivery as a group member.
//
// Gated on the same signals as the rest of the demo (roster dir presence).

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  linkSync,
  unlinkSync,
} from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import {
  IdentityKeyPair,
  PublicKey,
  PrivateKey,
  ProtocolAddress,
  ServerCertificate,
  SenderCertificate,
  SenderKeyRecord,
  SenderKeyDistributionMessage,
  SenderKeyStore,
  IdentityKeyStore,
  groupEncrypt,
} from '@signalapp/libsignal-client';
import type {
  CiphertextMessage,
  Direction,
  IdentityChange,
} from '@signalapp/libsignal-client';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';
import * as Bytes from '../Bytes.std.ts';
import { getRosterDir } from '../textsecure/personaRoster.preload.ts';
import {
  signalProtocolStore,
  GLOBAL_ZONE,
} from '../SignalProtocolStore.preload.ts';
import { SenderKeys } from '../LibSignalStores.node.ts';
import { QualifiedAddress } from '../types/QualifiedAddress.std.ts';
import { Address } from '../types/Address.std.ts';
import type { ServiceIdString } from '../types/ServiceId.std.ts';
import { normalizeServiceId } from '../types/ServiceId.std.ts';
import { itemStorage } from '../textsecure/Storage.preload.ts';

const log = createLogger('personasPhantom');

// Fixed demo identifiers. All instances must agree; these are constants (not
// secrets) so a late joiner that loads the bundle still uses the same address.
const PHANTOM_ACI: ServiceIdString = normalizeServiceId(
  '9f9f9f9f-0000-4000-8000-00000000face',
  'personasPhantom'
);
const PHANTOM_DEVICE_ID = 1;
const SHARED_DISTRIBUTION_ID = '9f9f9f9f-0000-4000-8000-0000000d15c0';

// Cert lifetime: minted once, must outlive any demo message's serverTimestamp.
const TEN_YEARS_MS = 10 * 365 * 24 * 3600 * 1000;

const BUNDLE_FILE = 'phantom-bundle.json';

// Recorded in item storage once this member's chain is installed, so a reboot keeps a
// chain that has walked forward instead of resetting it. Versioned: chains installed by
// the old receive-only (SKDM) path have no signing key and cannot send, so they must be
// replaced once.
const CHAIN_MARKER_VERSION = 'full-v1';

// Identifies a bundle. The trust root is minted fresh for each bundle and is public,
// so hashing it distinguishes bundles without writing key material to disk in a new
// place. Truncated: this only has to be distinct, not collision-resistant.
const bundleFingerprint = (mat: PhantomMaterial): string =>
  createHash('sha256')
    .update(mat.trustRootPublicBase64)
    .digest('hex')
    .slice(0, 16);

export const phantomAddress = (): ProtocolAddress =>
  ProtocolAddress.new(PHANTOM_ACI, PHANTOM_DEVICE_ID);

export const getPhantomAci = (): ServiceIdString => PHANTOM_ACI;
export const getSharedDistributionId = (): string => SHARED_DISTRIBUTION_ID;

// The immutable, shared phantom bundle (all fields base64). Written once to the
// roster dir; every instance loads the same one.
type SerializedBundle = {
  // Public key of the trust root we mint; goes into config.serverTrustRoots.
  trustRootPublic: string;
  // The shared phantom identity keypair (private state — the load-bearing secret).
  phantomIdentityKeyPair: string;
  // The shared sender certificate (binds phantom ACI/device/identity key).
  phantomCert: string;
  // Distribution id for the shared group sender key.
  distributionId: string;
  // SenderKeyDistributionMessage receivers process to install the receive chain.
  skdm: string;
  // Initial SenderKeyRecord senders load to seed the shared send chain.
  sendKeyRecord: string;
};

// A minimal in-memory SenderKeyStore (the phantom key is deliberately kept OUT
// of Desktop's DB store; the send chain is roster-dir-backed instead). Mirrors
// the store used in the bring-up gate.
class MemSenderKeyStore extends SenderKeyStore {
  #map = new Map<string, Uint8Array<ArrayBuffer>>();

  #key(sender: ProtocolAddress, distId: string): string {
    return `${sender.name()}::${sender.deviceId()}::${distId}`;
  }

  async saveSenderKey(
    sender: ProtocolAddress,
    distId: string,
    record: SenderKeyRecord
  ): Promise<void> {
    this.#map.set(this.#key(sender, distId), record.serialize());
  }

  async getSenderKey(
    sender: ProtocolAddress,
    distId: string
  ): Promise<SenderKeyRecord | null> {
    const bytes = this.#map.get(this.#key(sender, distId));
    return bytes ? SenderKeyRecord.deserialize(bytes) : null;
  }

  rawGet(
    sender: ProtocolAddress,
    distId: string
  ): Uint8Array<ArrayBuffer> | undefined {
    return this.#map.get(this.#key(sender, distId));
  }

  rawSet(
    sender: ProtocolAddress,
    distId: string,
    bytes: Uint8Array<ArrayBuffer>
  ): void {
    this.#map.set(this.#key(sender, distId), bytes);
  }
}

// An IdentityKeyStore that presents the PHANTOM identity as the LOCAL identity (so
// the sealed-sender authentication tag matches the phantom certificate for every
// member), while DELEGATING every recipient-facing lookup to Desktop's real identity
// store. `sealedSenderMultiRecipientEncrypt` requires each recipient's identity to be
// known (otherwise it reports "session not found"), and the real store already holds
// them — only the local *sending* identity is swapped. Proven at the libsignal level
// in scratchpad/phantom-gate-multi.mjs.
class PhantomIdentityStore extends IdentityKeyStore {
  #identity: IdentityKeyPair;
  #delegate: IdentityKeyStore;

  constructor(identity: IdentityKeyPair, delegate: IdentityKeyStore) {
    super();
    this.#identity = identity;
    this.#delegate = delegate;
  }

  async getIdentityKey(): Promise<PrivateKey> {
    // The load-bearing swap: the local identity is the phantom, so the outer
    // sealed-sender auth is byte-indistinguishable across all real senders.
    return this.#identity.privateKey;
  }

  async getLocalRegistrationId(): Promise<number> {
    return this.#delegate.getLocalRegistrationId();
  }

  async saveIdentity(
    name: ProtocolAddress,
    key: PublicKey
  ): Promise<IdentityChange> {
    return this.#delegate.saveIdentity(name, key);
  }

  async isTrustedIdentity(
    name: ProtocolAddress,
    key: PublicKey,
    direction: Direction
  ): Promise<boolean> {
    return this.#delegate.isTrustedIdentity(name, key, direction);
  }

  async getIdentity(name: ProtocolAddress): Promise<PublicKey | null> {
    return this.#delegate.getIdentity(name);
  }
}

// The loaded, live phantom material (deserialized once per process).
export type PhantomMaterial = {
  trustRootPublicBase64: string;
  phantomIdentity: IdentityKeyPair;
  phantomCert: SenderCertificate;
  distributionId: string;
  skdm: SenderKeyDistributionMessage;
  // The initial send-chain record (before roster-dir advancement is applied).
  initialSendKeyRecord: Uint8Array<ArrayBuffer>;
};

let material: PhantomMaterial | undefined;
let loadFailed = false;

function b64(bytes: Uint8Array<ArrayBuffer>): string {
  return Bytes.toBase64(bytes);
}
function unb64(s: string): Uint8Array<ArrayBuffer> {
  return Bytes.fromBase64(s);
}

// Mint a fresh bundle. One instance does this; the file is shared with the rest.
async function generateBundle(): Promise<SerializedBundle> {
  const trustRoot = IdentityKeyPair.generate();
  const serverKey = IdentityKeyPair.generate();
  const serverCert = ServerCertificate.new(1, serverKey.publicKey, trustRoot.privateKey);

  const phantomIdentity = IdentityKeyPair.generate();
  const expiration = Date.now() + TEN_YEARS_MS;
  const phantomCert = SenderCertificate.new(
    PHANTOM_ACI,
    null,
    PHANTOM_DEVICE_ID,
    phantomIdentity.publicKey,
    expiration,
    serverCert,
    serverKey.privateKey
  );

  const generatorStore = new MemSenderKeyStore();
  const skdm = await SenderKeyDistributionMessage.create(
    phantomAddress(),
    SHARED_DISTRIBUTION_ID,
    generatorStore
  );
  const sendKeyRecord = generatorStore.rawGet(phantomAddress(), SHARED_DISTRIBUTION_ID);
  if (!sendKeyRecord) {
    throw new Error('generateBundle: generator store missing sender key record');
  }

  return {
    trustRootPublic: b64(trustRoot.publicKey.serialize()),
    phantomIdentityKeyPair: b64(phantomIdentity.serialize()),
    phantomCert: b64(phantomCert.serialize()),
    distributionId: SHARED_DISTRIBUTION_ID,
    skdm: b64(skdm.serialize()),
    sendKeyRecord: b64(sendKeyRecord),
  };
}

function deserialize(bundle: SerializedBundle): PhantomMaterial {
  return {
    trustRootPublicBase64: bundle.trustRootPublic,
    phantomIdentity: IdentityKeyPair.deserialize(unb64(bundle.phantomIdentityKeyPair)),
    phantomCert: SenderCertificate.deserialize(unb64(bundle.phantomCert)),
    distributionId: bundle.distributionId,
    skdm: SenderKeyDistributionMessage.deserialize(unb64(bundle.skdm)),
    initialSendKeyRecord: unb64(bundle.sendKeyRecord),
  };
}

// Load the shared bundle, generating it if this is the first instance up. Idempotent:
// on a generate/load race the on-disk winner is adopted (we re-read after writing).
export async function ensurePhantomMaterial(): Promise<PhantomMaterial | undefined> {
  if (material || loadFailed) {
    return material;
  }
  const dir = getRosterDir();
  if (!dir) {
    return undefined;
  }
  const path = join(dir, BUNDLE_FILE);
  try {
    mkdirSync(dir, { recursive: true });

    let bundle: SerializedBundle | undefined;
    try {
      bundle = JSON.parse(readFileSync(path, 'utf8')) as SerializedBundle;
      log.info('ensurePhantomMaterial: loaded shared bundle');
    } catch {
      // Not present — mint it and publish with an atomic, EXCLUSIVE link (fails
      // if another instance already published). On EEXIST we adopt theirs, so all
      // instances converge on exactly one bundle even when they boot together.
      log.info('ensurePhantomMaterial: no bundle found; generating');
      const generated = await generateBundle();
      const tmp = `${path}.${process.pid}.tmp`;
      writeFileSync(tmp, JSON.stringify(generated, null, 2), 'utf8');
      try {
        linkSync(tmp, path);
        bundle = generated;
        log.info('ensurePhantomMaterial: published new bundle');
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === 'EEXIST') {
          bundle = JSON.parse(readFileSync(path, 'utf8')) as SerializedBundle;
          log.info('ensurePhantomMaterial: lost publish race; adopted existing');
        } else {
          throw error;
        }
      } finally {
        try {
          unlinkSync(tmp);
        } catch {
          // best effort
        }
      }
    }

    material = deserialize(bundle);
    // Log the DIRECTORY and the bundle FINGERPRINT together. Two instances can both
    // report "loaded shared bundle" while reading different files — which is exactly
    // what happens if one was launched before PERSONAS_ROSTER_DIR changed and another
    // after. Without these two values in the log, that case is invisible.
    log.info(
      `ensurePhantomMaterial: using bundle ${bundleFingerprint(material)} from ${dir}`
    );
    return material;
  } catch (error) {
    loadFailed = true;
    log.error(`ensurePhantomMaterial: failed: ${toLogFormat(error)}`);
    return undefined;
  }
}

// The phantom trust root public key (base64) to append to config.serverTrustRoots
// so the receive-side cert check admits phantom messages. Synchronous best-effort:
// returns undefined if the bundle isn't loaded yet (caller warms it at boot).
export function getPhantomTrustRootBase64(): string | undefined {
  return material?.trustRootPublicBase64;
}

// Warm the bundle at boot (before MessageReceiver construction reads trust roots).
export async function warmPhantomMaterial(): Promise<void> {
  if (!getRosterDir()) {
    return;
  }
  await ensurePhantomMaterial();
}

// Build the phantom identity store for the sealed-sender local identity, delegating
// recipient identity lookups to Desktop's real identity store (which already holds
// the group members' identities).
export function buildPhantomIdentityStore(
  delegate: IdentityKeyStore
): PhantomIdentityStore | undefined {
  if (!material) {
    return undefined;
  }
  return new PhantomIdentityStore(material.phantomIdentity, delegate);
}

const phantomQualifiedAddress = (ourAci: ServiceIdString): QualifiedAddress =>
  new QualifiedAddress(ourAci, Address.create(PHANTOM_ACI, PHANTOM_DEVICE_ID));

// THE SHARED PHANTOM CHAIN, ONE COPY PER MEMBER.
//
// Every member holds its own copy of the shared sender-key chain: the FULL private
// SenderKeyRecord, signing key included, in Desktop's sender-key store under the phantom
// address. The same record serves both directions:
//
//   receive  groupDecrypt walks the copy forward past every post it sees
//            (MessageReceiver's sealed-sender path, keyed by the phantom address);
//   send     groupEncrypt continues from the step after the newest post seen
//            (phantomGroupEncrypt below, queued on the same address).
//
// So members stay in step with no shared state: nothing is read from or written to the
// roster dir. Proven against libsignal: turn-taking posts all arrive, and a member that
// missed posts still decrypts later ones (it skips forward).
//
// THE ACCEPTED LIMITATION (design doc §4, Phase A1): two members posting at the same
// step, before either has seen the other's post, encrypt under the same message key.
// Recipients keep the first and drop the second as `DuplicatedMessage: old counter`.
// Posting is effectively serial; A2 (personas-group-crypto) is what lifts this.
//
// The old design kept separate chains: a send chain in a roster-dir file, and a
// receive-only chain installed from the bundle's SKDM. Receiving never advanced the
// send chain, which is what forced every member to share that file.
export async function installPhantomChain(): Promise<void> {
  const mat = await ensurePhantomMaterial();
  if (!mat) {
    return;
  }
  const ourAci = itemStorage.user.getAci();
  if (!ourAci) {
    log.warn('installPhantomChain: no ACI yet; skipping');
    return;
  }
  const address = phantomQualifiedAddress(ourAci);
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  const marker = `${bundleFingerprint(mat)}:${CHAIN_MARKER_VERSION}`;
  const installedFrom = itemStorage.get('personasPhantomChain');

  try {
    await signalProtocolStore.enqueueSenderKeyJob(
      address,
      async () => {
        const existing = await store.getSenderKey(
          phantomAddress(),
          mat.distributionId
        );
        // Keep a chain that has walked forward, but only when it provably came from
        // this bundle in the current format. `SHARED_DISTRIBUTION_ID` is a constant,
        // so a record from another bundle LOOKS valid while holding the wrong chain
        // key, and every phantom post would be dropped at this receiver.
        if (existing && installedFrom === marker) {
          log.info(`installPhantomChain: keeping chain ${marker}`);
          return;
        }
        if (existing) {
          log.warn(
            `installPhantomChain: replacing chain ${installedFrom ?? 'unknown'} with ${marker}`
          );
          // Delete first: saving over an existing record can leave a stale state
          // behind under the same chain id, and decryption keeps resolving to it.
          await signalProtocolStore.removeSenderKey(address, mat.distributionId);
        }
        await store.saveSenderKey(
          phantomAddress(),
          mat.distributionId,
          SenderKeyRecord.deserialize(mat.initialSendKeyRecord)
        );
        // Only after a successful install: a crash leaves no marker, read as stale.
        await itemStorage.put('personasPhantomChain', marker);
        log.info(`installPhantomChain: installed chain ${marker}`);
      },
      GLOBAL_ZONE
    );
  } catch (error) {
    log.error(`installPhantomChain: failed: ${toLogFormat(error)}`);
  }
}

// Encrypt a persona post under this member's copy of the shared phantom chain. Queued on
// the phantom address, the same key MessageReceiver decrypts phantom posts under, so a
// send and a receive in this process never interleave on the record.
export async function phantomGroupEncrypt(
  message: Uint8Array<ArrayBuffer>
): Promise<CiphertextMessage> {
  if (!material) {
    throw new Error('phantomGroupEncrypt: phantom material not loaded');
  }
  const { distributionId } = material;
  const ourAci = itemStorage.user.getCheckedAci();
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  return signalProtocolStore.enqueueSenderKeyJob(
    phantomQualifiedAddress(ourAci),
    () => groupEncrypt(phantomAddress(), distributionId, store, message),
    GLOBAL_ZONE
  );
}

export { MemSenderKeyStore, PhantomIdentityStore };
