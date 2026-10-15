// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas build: everything an installed client needs to reach our server, done by the
// app itself instead of a launch script.
//
// Active only when the build ships `config/personas.json` (written when packaging; see
// config/personas.example.json). Without it, nothing here runs and Desktop behaves as
// before — laptop runs (scripts/personas-run.sh) and the browser members
// (deploy/play/entrypoint.sh) configure themselves through env vars instead.
//
// At startup it:
//   1. mints a per-install CA + localhost certificate (once, kept in userData),
//   2. starts the localhost relay to the real server (personasRelay.node.ts),
//   3. picks this install's demo identity: a fake phone number not yet in the directory,
//      and a display name (kept in userData),
//   4. sets the PERSONAS_* environment the renderer's personas code reads, and
//   5. supplies the server settings (relay URL, CA, the test server's zkgroup params and
//      trust root) that replace the production values in the renderer config.

import { execFileSync } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { join } from 'node:path';

import { createLogger } from '../ts/logging/log.std.ts';
import { toLogFormat } from '../ts/types/errors.std.ts';
import { getAppRootDir } from '../ts/util/appRootDir.main.ts';
import { startPersonasRelay } from './personasRelay.node.ts';

const log = createLogger('personas');

export type PersonasBuildConfig = Readonly<{
  // host:port of our server, e.g. "signalserver.umiacs.umd.edu:443".
  upstream: string;
  upstreamTls: boolean;
  // SHA-256 of the server's proving keys (deploy/play/keys.sh); omit to generate locally.
  keysSha256?: string;
  // The TEST server's zkgroup params and sender-certificate trust root (not Signal's).
  serverPublicParams: string;
  serverTrustRoots: ReadonlyArray<string>;
}>;

export type PersonasServerSettings = Readonly<{
  serverUrl: string;
  certificateAuthority: string;
  serverPublicParams: string;
  serverTrustRoots: Array<string>;
}>;

type Identity = { number: string; name: string };

let buildConfig: PersonasBuildConfig | null | undefined;

export function getPersonasBuildConfig(): PersonasBuildConfig | undefined {
  if (buildConfig !== undefined) {
    return buildConfig ?? undefined;
  }
  const path = join(getAppRootDir(), 'config', 'personas.json');
  if (!existsSync(path)) {
    buildConfig = null;
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as PersonasBuildConfig;
    if (
      typeof parsed.upstream !== 'string' ||
      !/^[A-Za-z0-9.-]+:\d+$/.test(parsed.upstream) ||
      typeof parsed.upstreamTls !== 'boolean' ||
      typeof parsed.serverPublicParams !== 'string' ||
      !Array.isArray(parsed.serverTrustRoots) ||
      (parsed.keysSha256 !== undefined && !/^[0-9a-f]{64}$/.test(parsed.keysSha256))
    ) {
      throw new Error('missing or malformed fields');
    }
    buildConfig = parsed;
    return parsed;
  } catch (error) {
    // A personas build with a broken config must not fall back to talking to Signal.
    throw new Error(`config/personas.json is unusable: ${toLogFormat(error)}`);
  }
}

export function isPersonasBuild(): boolean {
  return getPersonasBuildConfig() !== undefined;
}

// --- 1. TLS material ------------------------------------------------------------------

function openssl(args: Array<string>, cwd: string): void {
  // /usr/bin/openssl is macOS's LibreSSL; it produces certificates rustls accepts.
  const binary = existsSync('/usr/bin/openssl') ? '/usr/bin/openssl' : 'openssl';
  execFileSync(binary, args, { cwd, stdio: 'ignore' });
}

function ensureTlsMaterial(dir: string): { key: string; cert: string; ca: string } {
  if (!existsSync(join(dir, 'leaf.pem'))) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // rustls (inside libsignal) wants a proper v3 CA and a non-CA leaf with SANs.
    openssl(
      [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
        '-keyout', 'ca.key', '-out', 'ca.pem', '-subj', '/CN=Signal Personas local CA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
      ],
      dir
    );
    openssl(
      ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=localhost'],
      dir
    );
    writeFileSync(
      join(dir, 'leaf.ext'),
      'basicConstraints=CA:FALSE\n' +
        'keyUsage=critical,digitalSignature,keyEncipherment\n' +
        'extendedKeyUsage=serverAuth\n' +
        'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
    );
    openssl(
      [
        'x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
        '-CAcreateserial', '-days', '825', '-extfile', 'leaf.ext', '-out', 'leaf.pem',
      ],
      dir
    );
    log.info('minted the local relay certificate');
  }
  return {
    key: readFileSync(join(dir, 'leaf.key'), 'utf8'),
    cert: readFileSync(join(dir, 'leaf.pem'), 'utf8'),
    ca: readFileSync(join(dir, 'ca.pem'), 'utf8'),
  };
}

// --- 3. identity ----------------------------------------------------------------------

function listDirectoryNumbers(port: number, ca: string): Promise<Set<string>> {
  return new Promise(resolve => {
    const req = request(
      { host: '127.0.0.1', port, path: '/personas/directory', ca, servername: 'localhost', timeout: 10_000 },
      res => {
        let raw = '';
        res.setEncoding('utf8');
        res.on('data', chunk => {
          raw += chunk;
        });
        res.on('end', () => {
          try {
            const list = JSON.parse(raw) as Array<{ e164?: string }>;
            resolve(new Set(list.map(entry => entry.e164 ?? '')));
          } catch {
            resolve(new Set());
          }
        });
      }
    );
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(new Set()));
    req.end();
  });
}

// This install's demo identity, chosen once. The number is fake: the test server does
// not send SMS, and registration uses its stub code. It is drawn from the fictional
// +1 202 555 range and checked against the directory, because registering a number that
// is already taken would take over that tester's account on the test server.
async function ensureIdentity(path: string, port: number, ca: string): Promise<Identity> {
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, 'utf8')) as Identity;
  }
  const taken = await listDirectoryNumbers(port, ca);
  let number = '';
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const candidate = `+1202555${String(randomInt(0, 10_000)).padStart(4, '0')}`;
    if (!taken.has(candidate)) {
      number = candidate;
      break;
    }
  }
  if (!number) {
    throw new Error('could not find a free demo number');
  }
  const identity: Identity = { number, name: `member-${number.slice(-4)}` };
  writeFileSync(path, JSON.stringify(identity, null, 2), { mode: 0o600 });
  log.info(`chose demo identity ${identity.name}`);
  return identity;
}

// --- startup --------------------------------------------------------------------------

let runtime: Promise<PersonasServerSettings | undefined> | undefined;

// Idempotent; resolves undefined for a non-personas build.
export function startPersonasRuntime(userDataPath: string): Promise<PersonasServerSettings | undefined> {
  runtime ??= (async () => {
    const config = getPersonasBuildConfig();
    if (!config) {
      return undefined;
    }
    const { key, cert, ca } = ensureTlsMaterial(join(userDataPath, 'personas-tls'));
    const port = await startPersonasRelay({
      key,
      cert,
      upstream: config.upstream,
      upstreamTls: config.upstreamTls,
    });
    const identity = await ensureIdentity(join(userDataPath, 'personas-identity.json'), port, ca);

    // What the renderer's personas code reads (see scripts/personas-run.sh for each).
    process.env.PERSONAS_AUTO_REGISTER = identity.number;
    process.env.PERSONAS_DISPLAY_NAME = identity.name;
    process.env.PERSONAS_KEYS_DIR = join(userDataPath, 'personas-keys');
    process.env.PERSONAS_SKIP_EMPTY_QUEUE_WAIT = '1';
    process.env.PERSONAS_FORCE_ACCESS_KEYS = '0';
    if (config.keysSha256) {
      process.env.PERSONAS_KEYS_SHA256 = config.keysSha256;
    }

    return {
      serverUrl: `https://127.0.0.1:${port}`,
      certificateAuthority: ca,
      serverPublicParams: config.serverPublicParams,
      serverTrustRoots: [...config.serverTrustRoots],
    };
  })();
  return runtime;
}
