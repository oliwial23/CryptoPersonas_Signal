// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas demo: the shared Groth16 proving keys, fetched from our server and checked
// against a pinned hash.
//
// Every member must prove and verify against an IDENTICAL key set, or every proof is
// rejected on ingest. Members on one machine used to share a keys folder; installed
// clients cannot, so each downloads the canonical file (~51 MB) once from
// `<server>/personas/keys/merkle_groth16_keys.bin` and accepts it only if its SHA-256
// equals PERSONAS_KEYS_SHA256. The file then sits where `ensure_merkle_keys` looks for
// it, so the engine loads it instead of generating its own.
//
// TRUST: these keys come from a one-time setup, and whoever generates them could forge
// proofs. The pin protects against a swapped or corrupted download, not against the
// generator. Generating them on our server puts that trust in one known place (it used
// to be whichever member happened to boot first).
//
// Without a pinned hash nothing changes: the engine generates or loads keys locally,
// which is right for a single-machine run.

import { createHash } from 'node:crypto';
import {
  createReadStream,
  createWriteStream,
  existsSync,
  mkdirSync,
  renameSync,
  rmSync,
} from 'node:fs';
import { request } from 'node:https';
import { dirname, join } from 'node:path';

import { createLogger } from '../logging/log.std.ts';
import { toLogFormat } from '../types/errors.std.ts';

const log = createLogger('personasKeys');

// Where ensure_merkle_keys reads the bundle (personas-bulletin merkle/params.rs).
const KEYS_RELATIVE_PATH = join(
  'params',
  'serverless-merkle',
  'merkle_groth16_keys.bin'
);
const KEYS_URL_PATH = '/personas/keys/merkle_groth16_keys.bin';
// Generous: the server is behind a load balancer and the file is ~51 MB. An idle socket
// for this long is a stalled transfer, not a slow one.
const IDLE_TIMEOUT_MS = 60_000;
const SHA256_HEX = /^[0-9a-f]{64}$/;

export function getPinnedKeysSha256(): string | undefined {
  const pinned = process.env.PERSONAS_KEYS_SHA256?.trim().toLowerCase();
  if (!pinned) {
    return undefined;
  }
  if (!SHA256_HEX.test(pinned)) {
    log.error('PERSONAS_KEYS_SHA256 is not a 64-character hex SHA-256; ignoring it');
    return undefined;
  }
  return pinned;
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(path)
      .on('data', chunk => hash.update(chunk))
      .on('error', reject)
      .on('end', () => resolve(hash.digest('hex')));
  });
}

// Stream the file to `dest`. Same host, port and private CA as the chat server: the
// request goes through the localhost relay to our gateway.
function download(dest: string): Promise<void> {
  const { serverUrl, certificateAuthority } = window.SignalContext.config;
  const url = new URL(KEYS_URL_PATH, serverUrl);
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      { method: 'GET', ca: certificateAuthority, timeout: IDLE_TIMEOUT_MS },
      res => {
        if (res.statusCode !== 200) {
          res.resume();
          reject(new Error(`GET ${KEYS_URL_PATH}: HTTP ${res.statusCode}`));
          return;
        }
        const out = createWriteStream(dest);
        res.pipe(out);
        out.on('finish', () => resolve());
        out.on('error', reject);
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error('proving-keys download stalled')));
    req.on('error', reject);
    req.end();
  });
}

let pending: Promise<boolean> | undefined;

// Make sure `keysDir` holds the pinned proving keys, downloading them if needed.
// Resolves true when the engine may be built: the keys are in place and verified, or no
// hash is pinned (local keys, as before). Resolves false on failure; a later call tries
// again.
export async function ensureProvingKeys(keysDir: string): Promise<boolean> {
  pending ??= installPinnedKeys(keysDir);
  const attempt = pending;
  const ok = await attempt;
  // A failed attempt must not stick: clear it so the next call retries.
  if (!ok && pending === attempt) {
    pending = undefined;
  }
  return ok;
}

async function installPinnedKeys(keysDir: string): Promise<boolean> {
  const pinned = getPinnedKeysSha256();
  if (!pinned) {
    return true;
  }
  const path = join(keysDir, KEYS_RELATIVE_PATH);
  const tmp = `${path}.download-${process.pid}`;
  try {
    return await placePinnedKeys(path, tmp, pinned);
  } catch (error) {
    rmSync(tmp, { force: true });
    log.error(`ensureProvingKeys: ${toLogFormat(error)}`);
    return false;
  }
}

async function placePinnedKeys(
  path: string,
  tmp: string,
  pinned: string
): Promise<boolean> {
  if (existsSync(path)) {
    const have = await sha256File(path);
    if (have === pinned) {
      log.info('ensureProvingKeys: pinned keys already present');
      return true;
    }
    // Keys that do not match the group's are worse than none: every proof made with
    // them is rejected. Keep the file for inspection, but out of the engine's way.
    log.warn(
      `ensureProvingKeys: local keys ${have.slice(0, 12)} do not match the pinned ` +
        `${pinned.slice(0, 12)}; replacing them`
    );
    renameSync(path, `${path}.mismatched-${have.slice(0, 12)}`);
  }

  mkdirSync(dirname(path), { recursive: true });
  log.info('ensureProvingKeys: downloading the proving keys');
  const started = Date.now();
  await download(tmp);
  const got = await sha256File(tmp);
  if (got !== pinned) {
    throw new Error(
      `downloaded keys hash to ${got.slice(0, 12)}, expected ${pinned.slice(0, 12)}`
    );
  }
  // Rename only after verifying, so the engine can never load a partial or wrong file.
  renameSync(tmp, path);
  log.info(`ensureProvingKeys: verified and installed in ${Date.now() - started}ms`);
  return true;
}
