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
  renameSync,
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
  processSenderKeyDistributionMessage,
} from '@signalapp/libsignal-client';
import type { Direction, IdentityChange } from '@signalapp/libsignal-client';

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
// The advancing shared send chain lives apart from the immutable bundle so
// senders can load-before / save-after (serial-posting coordination).
const SEND_STATE_FILE = 'phantom-sendkey-state.b64';

// Which BUNDLE an instance's installed receive chain came from, one marker file per
// account. See installPhantomReceiveKey for why presence of a record is not enough.
const receiveMarkerFile = (aci: string): string =>
  `phantom-receive-${aci}.id`;

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

// Roster-dir-backed shared SEND chain: load the latest advanced state (or the
// bundle's initial record) into a fresh store, returning the store + a saver that
// persists the advanced state after groupEncrypt. Serial posting is assumed.
export function loadPhantomSendStore(): { store: MemSenderKeyStore; save: () => void } | undefined {
  const dir = getRosterDir();
  if (!dir || !material) {
    return undefined;
  }
  const store = new MemSenderKeyStore();
  const statePath = join(dir, SEND_STATE_FILE);
  const fingerprint = bundleFingerprint(material);

  // The send state is TAGGED with the bundle it belongs to, as `<fingerprint>:<base64>`.
  //
  // Same trap as the receive side, in the other direction: `SHARED_DISTRIBUTION_ID` is a
  // constant, so an advanced chain left over from a previous bundle looks loadable while
  // carrying the wrong chain key. Senders would then encrypt with a chain no recipient
  // installed, and every post would be dropped at the receiver with no sending error.
  //
  // AN UNTAGGED FILE IS ADOPTED, NOT DISCARDED. It predates tagging; that makes its
  // provenance unrecorded, not wrong. Discarding it was a real bug:
  //
  //   A sender-key RECEIVE chain only ever moves forward. Resetting the SEND chain to
  //   the bundle's initial record while recipients sat at counter 8 made every post
  //   replay counters 3, 4, 5 — which libsignal rejects as
  //   `DuplicatedMessage: message with old counter 8 / 3`. Posts stopped arriving again,
  //   now for the opposite reason, and only until the chain climbed back past 8.
  //
  // The asymmetry was the mistake: the receive side keeps its chain whenever the marker
  // matches the bundle, so the two sides must agree on what counts as stale. Rewinding
  // one while keeping the other can only break them.
  //
  // So discard ONLY on a tag that is present and DIFFERENT — the one case that really
  // does mean another bundle. An untagged file is tagged in place on the next save.
  // INSTRUMENTATION. The chain counter is the only thing that explains a
  // `DuplicatedMessage: old counter N / M`, and libsignal does not expose the iteration
  // from JS — so log a short digest of the record plus its length. Two sends that log
  // the SAME digest encrypted at the same counter, which is what a lost save or a
  // cross-process race looks like. Without this the failure is only visible from the
  // recipient's error, which cannot distinguish the two causes.
  const digest = (bytes: Uint8Array<ArrayBuffer>): string =>
    `${createHash('sha256').update(bytes).digest('hex').slice(0, 12)}/${bytes.length}b`;

  let recordBytes: Uint8Array<ArrayBuffer>;
  let origin: string;
  try {
    const raw = readFileSync(statePath, 'utf8').trim();
    const separator = raw.indexOf(':');
    const tag = separator === -1 ? undefined : raw.slice(0, separator);
    origin = 'state file';
    if (tag === undefined) {
      log.info(
        'loadPhantomSendStore: adopting an untagged send chain (written before ' +
        `tagging existed); it will be tagged ${fingerprint} on the next save.`
      );
      recordBytes = unb64(raw);
    } else if (tag !== fingerprint) {
      log.warn(
        `loadPhantomSendStore: send state belongs to bundle ${tag}, but this bundle ` +
        `is ${fingerprint}; starting a fresh send chain. Recipients must also reinstall ` +
        'their receive chains, which the marker check does on their next boot.'
      );
      recordBytes = material.initialSendKeyRecord;
      origin = 'BUNDLE INITIAL (wrong bundle tag)';
    } else {
      recordBytes = unb64(raw.slice(separator + 1));
    }
  } catch (error) {
    // Distinguish "no file yet" from "file unreadable". The first is normal on the very
    // first send; seeing it on EVERY send means saves are not landing, which resets the
    // chain to counter 0 each time and makes every post a duplicate at the receiver.
    const missing = (error as NodeJS.ErrnoException)?.code === 'ENOENT';
    origin = missing
      ? 'BUNDLE INITIAL (no state file)'
      : `BUNDLE INITIAL (unreadable: ${toLogFormat(error)})`;
    recordBytes = material.initialSendKeyRecord;
  }
  store.rawSet(phantomAddress(), material.distributionId, recordBytes);
  log.info(
    `loadPhantomSendStore: loaded chain ${digest(recordBytes)} from ${origin} [${statePath}]`
  );

  const save = () => {
    const advanced = store.rawGet(phantomAddress(), material!.distributionId);
    if (!advanced) {
      log.error(
        'loadPhantomSendStore/save: store has no record to persist — the shared chain ' +
        'will restart from the bundle on the next send, and every post will be a ' +
        'duplicate at the receiver.'
      );
      return;
    }
    try {
      const tmp = `${statePath}.${process.pid}.tmp`;
      writeFileSync(tmp, `${fingerprint}:${b64(advanced)}`, 'utf8');
      renameSync(tmp, statePath);
      log.info(
        `loadPhantomSendStore/save: advanced ${digest(recordBytes)} -> ${digest(advanced)}`
      );
    } catch (error) {
      // Previously unguarded: a failed write threw out of the send job, so the post
      // appeared to fail for an unrelated reason while the chain silently did not move.
      log.error(
        `loadPhantomSendStore/save: FAILED to persist the advanced chain to ${statePath}: ` +
        `${toLogFormat(error)}. The next send will reuse counter ${digest(recordBytes)}.`
      );
    }
  };
  return { store, save };
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

// Boot-time install of the shared phantom RECEIVE chain into Desktop's real sender-key
// store, so an incoming phantom SenderKey message (sealed under PHANTOM_ACI) decrypts
// via `groupDecrypt`. Mirrors what `#handleSenderKeyDistributionMessage` would do, but
// for the pre-shared bundle SKDM instead of a wire one.
//
// IDEMPOTENT, BUT ONLY PER BUNDLE. An earlier version skipped whenever a record already
// existed, to avoid resetting a ratcheted receive chain on reboot. That is right as long
// as the bundle never changes — but `SHARED_DISTRIBUTION_ID` is a hardcoded constant, so
// a NEW bundle reuses the same distribution id while carrying a DIFFERENT chain key.
// The guard then saw the old record, kept the old chain, and never installed the new one.
//
// The symptom was badly misleading: senders encrypted with the new chain, recipients
// decrypted with the old, and every anonymous and pseudonymous post was dropped at the
// receiver while still rendering locally for its sender. No error appeared on the sending
// side, and the certificate check passed, because the trust root was fine.
//
// A bundle is reminted whenever the roster dir loses it — which happened routinely while
// the dir defaulted to /tmp. So this was reachable from an ordinary reboot.
//
// Fix: remember WHICH bundle the installed chain came from and reinstall when it differs.
// A ratcheted chain is still preserved across restarts on the same bundle, which is what
// the original guard was protecting.
export async function installPhantomReceiveKey(): Promise<void> {
  const mat = await ensurePhantomMaterial();
  if (!mat) {
    return;
  }
  const ourAci = itemStorage.user.getAci();
  if (!ourAci) {
    log.warn('installPhantomReceiveKey: no ACI yet; skipping');
    return;
  }
  const address = new QualifiedAddress(
    ourAci,
    Address.create(PHANTOM_ACI, PHANTOM_DEVICE_ID)
  );
  const store = new SenderKeys({
    signalProtocolStore,
    ourServiceId: ourAci,
    zone: GLOBAL_ZONE,
  });
  const dir = getRosterDir();
  const fingerprint = bundleFingerprint(mat);
  const markerPath = dir ? join(dir, receiveMarkerFile(ourAci)) : undefined;
  let installedFrom: string | undefined;
  if (markerPath) {
    try {
      installedFrom = readFileSync(markerPath, 'utf8').trim();
    } catch {
      // No marker: either a first run, or a record installed before this check
      // existed. Both are handled below — an unknown provenance is treated as stale.
      installedFrom = undefined;
    }
  }

  try {
    await signalProtocolStore.enqueueSenderKeyJob(
      address,
      async () => {
        const existing = await store.getSenderKey(
          phantomAddress(),
          mat.distributionId
        );
        // Keep the ratcheted chain ONLY when it provably came from this bundle.
        if (existing && installedFrom === fingerprint) {
          log.info(
            `installPhantomReceiveKey: already installed from bundle ${fingerprint}; keeping chain`
          );
          return;
        }
        if (existing) {
          // The loud case. Overwriting a receive chain loses any ratchet position,
          // which is correct here — the old chain belongs to a bundle nobody is
          // sending with any more — but it is worth saying out loud, because it is
          // also the signature of a roster dir that keeps being recreated.
          log.warn(
            `installPhantomReceiveKey: existing chain is from bundle ${installedFrom ?? 'unknown'}, ` +
            `but the current bundle is ${fingerprint}. Reinstalling — a stale chain ` +
            'silently drops every phantom message at the receiver.'
          );
          // DELETE IT FIRST. `processSenderKeyDistributionMessage` ADDS a state to the
          // SenderKeyRecord; it does not replace the record. The bundle's SKDM has a
          // fixed chain id, so reprocessing it layers a fresh state alongside the old
          // ratcheted one under the SAME id, and decryption kept resolving to the stale
          // state. The reinstall then logged success while changing nothing:
          //
          //   receive chain stuck at counter 8, senders restarting from 0, every post
          //   rejected as `DuplicatedMessage: message with old counter 8 / 0` — and no
          //   amount of resetting the SEND side could ever satisfy it.
          //
          // Removing the record makes the reinstall real.
          await signalProtocolStore.removeSenderKey(address, mat.distributionId);
          log.info(
            'installPhantomReceiveKey: removed the stale sender key record so the ' +
            'reinstall actually replaces it'
          );
        }
        await processSenderKeyDistributionMessage(
          phantomAddress(),
          mat.skdm,
          store
        );
        if (markerPath) {
          // Written only after a successful install, so a crash mid-install leaves the
          // marker absent (treated as stale) rather than falsely claiming this bundle.
          try {
            const tmp = `${markerPath}.${process.pid}.tmp`;
            writeFileSync(tmp, fingerprint, 'utf8');
            renameSync(tmp, markerPath);
          } catch (error) {
            // Non-fatal: the next boot reinstalls rather than wrongly keeping a chain.
            log.warn(
              `installPhantomReceiveKey: could not record bundle marker: ${toLogFormat(error)}`
            );
          }
        }
        log.info(
          `installPhantomReceiveKey: installed shared phantom receive key from bundle ${fingerprint}`
        );
      },
      GLOBAL_ZONE
    );
  } catch (error) {
    log.error(`installPhantomReceiveKey: failed: ${toLogFormat(error)}`);
  }
}

export { MemSenderKeyStore, PhantomIdentityStore };
