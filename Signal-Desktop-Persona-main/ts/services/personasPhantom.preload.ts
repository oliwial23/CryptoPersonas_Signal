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
// This module owns the bundle and its distribution, with no shared folder or server:
//
//   MINT     the member who creates a group mints the bundle (mintPhantomBundle);
//   SHARE    any member holding it sends it 1:1 to each fellow group member who does
//            not have it yet, over the pairwise Double Ratchet (distributePhantomBundle);
//   ADOPT    a member adopts the FIRST bundle it gets from a fellow group member and
//            refuses any different one afterwards (adoptPhantomBundle).
//
// The bundle lives in item storage (the encrypted DB). Delivery rides Desktop's real
// GroupV2 sender-key path — the phantom lives only INSIDE the sealed envelope; the real
// account still authorizes delivery as a group member.
//
// ONE BUNDLE PER INSTALL: the engine is single-conversation, so a member takes part in
// one personas group. A second group reuses the same bundle.
//
// Gated on the same signals as the rest of the demo (isPersonasEngineEnabled's env).

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
import type { ConversationModel } from '../models/conversations.preload.ts';
import { isGroupV2, isMe } from '../util/whatTypeOfConversation.dom.ts';
import {
  encodePhantomBundle,
  type PersonaPhantomBundleWire,
} from './personasCarriage.std.ts';
import {
  PHANTOM_SENDER_ACI,
  setExpectedPhantomCertificate,
} from './personasPhantomCert.std.ts';
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
  PHANTOM_SENDER_ACI,
  'personasPhantom'
);
const PHANTOM_DEVICE_ID = 1;
const SHARED_DISTRIBUTION_ID = '9f9f9f9f-0000-4000-8000-0000000d15c0';

// Cert lifetime: minted once, must outlive any demo message's serverTimestamp.
const TEN_YEARS_MS = 10 * 365 * 24 * 3600 * 1000;

// The barrier period a minted bundle carries (PERSONAS_BARRIER_PERIOD_MS overrides).
const DEFAULT_BARRIER_PERIOD_MS = 10_000;

// How often a bundle holder checks its groups for members who still need the bundle.
const DISTRIBUTION_INTERVAL_MS = 30_000;

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

// The immutable, shared phantom bundle (all fields base64), as kept in item storage.
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
  // The shared barrier schedule; the creator picks it so every member agrees.
  schedule: { anchorMs: number; periodMs: number };
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
  // The chain record this member's copy is installed from: the minter's fresh chain, or
  // the distributor's position at the time it sent the bundle.
  initialSendKeyRecord: Uint8Array<ArrayBuffer>;
  schedule: { anchorMs: number; periodMs: number };
};

let material: PhantomMaterial | undefined;
let bundleJson: string | undefined;
const readyListeners: Array<(mat: PhantomMaterial) => void> = [];

function isPersonasMode(): boolean {
  return Boolean(
    process.env.PERSONAS_AUTO_REGISTER || process.env.PERSONAS_KEYS_DIR
  );
}

function b64(bytes: Uint8Array<ArrayBuffer>): string {
  return Bytes.toBase64(bytes);
}
function unb64(s: string): Uint8Array<ArrayBuffer> {
  return Bytes.fromBase64(s);
}

// Mint a fresh bundle. Only the creator of a group does this; everyone else adopts.
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

  const period = Number(process.env.PERSONAS_BARRIER_PERIOD_MS);
  return {
    trustRootPublic: b64(trustRoot.publicKey.serialize()),
    phantomIdentityKeyPair: b64(phantomIdentity.serialize()),
    phantomCert: b64(phantomCert.serialize()),
    distributionId: SHARED_DISTRIBUTION_ID,
    skdm: b64(skdm.serialize()),
    sendKeyRecord: b64(sendKeyRecord),
    schedule: {
      anchorMs: Date.now(),
      periodMs: period > 0 ? period : DEFAULT_BARRIER_PERIOD_MS,
    },
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
    schedule: bundle.schedule,
  };
}

function activate(json: string, how: string): PhantomMaterial {
  const mat = deserialize(JSON.parse(json) as SerializedBundle);
  material = mat;
  bundleJson = json;
  setExpectedPhantomCertificate(mat.phantomCert.serialize());
  log.info(`phantom bundle ${bundleFingerprint(mat)} ${how}`);
  return mat;
}

// The bundle this member holds, from item storage. undefined until this member has
// minted (created a group) or adopted (received one from a fellow group member).
export async function ensurePhantomMaterial(): Promise<PhantomMaterial | undefined> {
  if (material || !isPersonasMode()) {
    return material;
  }
  const json = itemStorage.get('personasPhantomBundle');
  if (!json) {
    return undefined;
  }
  try {
    return activate(json, 'loaded from storage');
  } catch (error) {
    log.error(`ensurePhantomMaterial: stored bundle unreadable: ${toLogFormat(error)}`);
    return undefined;
  }
}

export function hasPhantomMaterial(): boolean {
  return material !== undefined;
}

export function getPhantomSchedule(): PhantomMaterial['schedule'] | undefined {
  return material?.schedule;
}

// Called with the material once it is available: immediately if it already is, or when
// it is minted/adopted later. Background uses this to admit the trust root and build the
// engine on the bundle's schedule.
export function onPhantomMaterialReady(listener: (mat: PhantomMaterial) => void): void {
  readyListeners.push(listener);
  if (material) {
    listener(material);
  }
}

async function commitBundle(json: string, how: string): Promise<PhantomMaterial> {
  await itemStorage.put('personasPhantomBundle', json);
  const mat = activate(json, how);
  await installPhantomChain();
  for (const listener of readyListeners) {
    try {
      listener(mat);
    } catch (error) {
      log.error(`phantom ready listener failed: ${toLogFormat(error)}`);
    }
  }
  return mat;
}

// The group creator mints the bundle. Idempotent: a member that already holds one keeps
// it (one bundle per install).
export async function mintPhantomBundle(): Promise<PhantomMaterial | undefined> {
  if (!isPersonasMode()) {
    return undefined;
  }
  const existing = await ensurePhantomMaterial();
  if (existing) {
    return existing;
  }
  return commitBundle(JSON.stringify(await generateBundle()), 'minted');
}

export type AdoptResult = 'adopted' | 'duplicate' | 'conflict' | 'disabled';

// Adopt a bundle received from a fellow group member. The caller must already have
// checked that the sender shares a group with us (isFellowGroupMember).
//
// FIRST ONE WINS, AND IT IS FINAL. A second, different bundle is refused: switching
// would silently strand our chain, and a member being fed a different certificate is
// exactly what tagging would look like. Logged loudly instead.
export async function adoptPhantomBundle(
  wire: PersonaPhantomBundleWire,
  from: string
): Promise<AdoptResult> {
  if (!isPersonasMode()) {
    return 'disabled';
  }
  const existing = await ensurePhantomMaterial();
  if (existing) {
    const same =
      existing.trustRootPublicBase64 === wire.trustRootPublic &&
      b64(existing.phantomCert.serialize()) === wire.phantomCert;
    if (same) {
      log.info(`adoptPhantomBundle: already hold this bundle; ignoring copy from ${from}`);
      return 'duplicate';
    }
    log.error(
      `adoptPhantomBundle: REFUSED a different phantom bundle from ${from}. We hold ` +
        `${bundleFingerprint(existing)}. A second bundle means either two groups minted ` +
        'separately or someone is handing members different certificates; either way, ' +
        'switching would strand this member.'
    );
    return 'conflict';
  }
  const bundle: SerializedBundle = {
    trustRootPublic: wire.trustRootPublic,
    phantomIdentityKeyPair: wire.phantomIdentityKeyPair,
    phantomCert: wire.phantomCert,
    distributionId: wire.distributionId,
    skdm: wire.skdm,
    sendKeyRecord: wire.chainRecord,
    schedule: wire.schedule,
  };
  await commitBundle(JSON.stringify(bundle), `adopted from ${from}`);
  return 'adopted';
}

// Whether a conversation (the 1:1 chat a bundle arrived in) belongs to someone who is a
// full member of one of our groups. Bundles from anyone else are ignored.
export function isFellowGroupMember(conversationId: string): boolean {
  return window.ConversationController.getAll().some(
    group =>
      isGroupV2(group.attributes) &&
      !group.get('left') &&
      group.getMemberConversationIds().has(conversationId)
  );
}

// Bundles that arrived from someone who was not (yet) a fellow group member.
//
// The creator sends the bundle the moment it adds a member, so the 1:1 bundle can beat
// the group update that tells this member it was added. Dropping it then would be
// permanent: the sender has already marked us as sent. So it is held and re-checked on
// every sweep, and adopted once the sender shows up as a fellow member. In memory only,
// bounded, and never adopted without that check.
const MAX_PENDING_BUNDLES = 8;
const pendingBundles = new Map<
  string,
  { wire: PersonaPhantomBundleWire; from: string }
>();

export function holdPendingBundle(
  conversationId: string,
  wire: PersonaPhantomBundleWire,
  from: string
): void {
  if (!pendingBundles.has(conversationId) && pendingBundles.size >= MAX_PENDING_BUNDLES) {
    log.warn(`holdPendingBundle: too many pending bundles; dropping the one from ${from}`);
    return;
  }
  pendingBundles.set(conversationId, { wire, from });
  log.info(`holdPendingBundle: holding a bundle from ${from} until they share a group with us`);
}

async function retryPendingBundles(): Promise<void> {
  for (const [conversationId, { wire, from }] of [...pendingBundles]) {
    if (material) {
      pendingBundles.clear();
      return;
    }
    if (isFellowGroupMember(conversationId)) {
      pendingBundles.delete(conversationId);
      // oxlint-disable-next-line no-await-in-loop
      const result = await adoptPhantomBundle(wire, from);
      log.info(`retryPendingBundles: bundle from ${from}: ${result}`);
    }
  }
}

// This member's current position on the shared chain, for handing to a new member.
async function readCurrentChainRecord(
  mat: PhantomMaterial
): Promise<Uint8Array<ArrayBuffer> | undefined> {
  const ourAci = itemStorage.user.getAci();
  if (!ourAci) {
    return undefined;
  }
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  return signalProtocolStore.enqueueSenderKeyJob(
    phantomQualifiedAddress(ourAci),
    async () =>
      (await store.getSenderKey(phantomAddress(), mat.distributionId))?.serialize(),
    GLOBAL_ZONE
  );
}

let distributing = false;

// Send the bundle 1:1 to every full member of our groups who has not been sent it yet.
// Any holder distributes, not only the creator, so the group does not depend on the
// creator staying online. Recipients ignore copies of a bundle they already hold.
export async function distributePhantomBundle(): Promise<void> {
  const mat = material;
  if (!mat || !bundleJson || distributing) {
    return;
  }
  distributing = true;
  try {
    const fingerprint = bundleFingerprint(mat);
    const sent = new Set(itemStorage.get('personasPhantomSentTo') ?? []);
    const pending = new Map<string, ConversationModel>();
    for (const group of window.ConversationController.getAll()) {
      if (!isGroupV2(group.attributes) || group.get('left')) {
        continue;
      }
      for (const member of group.getMembers()) {
        const serviceId = member.getServiceId();
        if (!serviceId || isMe(member.attributes)) {
          continue;
        }
        if (!sent.has(`${fingerprint}:${serviceId}`)) {
          pending.set(serviceId, member);
        }
      }
    }
    if (pending.size === 0) {
      return;
    }

    const chainRecord = await readCurrentChainRecord(mat);
    if (!chainRecord) {
      log.warn('distributePhantomBundle: no installed chain to share yet');
      return;
    }
    const stored = JSON.parse(bundleJson) as SerializedBundle;
    const body = encodePhantomBundle({
      v: 1,
      trustRootPublic: stored.trustRootPublic,
      phantomIdentityKeyPair: stored.phantomIdentityKeyPair,
      phantomCert: stored.phantomCert,
      distributionId: stored.distributionId,
      skdm: stored.skdm,
      chainRecord: b64(chainRecord),
      schedule: stored.schedule,
    });

    // Sequential on purpose: each recipient is marked sent (and persisted) only after
    // its own send succeeded, so a failure retries just that member next sweep.
    for (const [serviceId, member] of pending) {
      try {
        // oxlint-disable-next-line no-await-in-loop
        await member.enqueueMessageForSend(
          { body, attachments: [] },
          // Key material: never shown, and only ever sent 1:1.
          { hideFromTimeline: true }
        );
        sent.add(`${fingerprint}:${serviceId}`);
        // oxlint-disable-next-line no-await-in-loop
        await itemStorage.put('personasPhantomSentTo', [...sent]);
        log.info(`distributePhantomBundle: sent bundle ${fingerprint} to ${serviceId}`);
      } catch (error) {
        log.warn(
          `distributePhantomBundle: send to ${serviceId} failed (retrying next sweep): ` +
            toLogFormat(error)
        );
      }
    }
  } finally {
    distributing = false;
  }
}

let distributionTimer: NodeJS.Timeout | undefined;

// Start the periodic sweep (boot, after registration): adopt held bundles whose sender
// has since become a fellow member, then distribute ours. Cheap when there is nothing
// to do.
export function startPhantomDistribution(): void {
  if (!isPersonasMode() || distributionTimer) {
    return;
  }
  const sweep = async () => {
    await retryPendingBundles();
    await distributePhantomBundle();
  };
  void sweep();
  distributionTimer = setInterval(() => {
    void sweep();
  }, DISTRIBUTION_INTERVAL_MS);
}

// The phantom trust root public key (base64), for the receiver's trust-root set.
// undefined until this member holds a bundle.
export function getPhantomTrustRootBase64(): string | undefined {
  return material?.trustRootPublicBase64;
}

// Load a stored bundle at boot, before MessageReceiver construction reads trust roots.
export async function warmPhantomMaterial(): Promise<void> {
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
