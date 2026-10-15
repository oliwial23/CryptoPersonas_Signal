// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Package the installable Signal Personas client: an unsigned (ad-hoc signed) Apple
// Silicon .dmg that talks only to our server.
//
//   node scripts/personas-package.mjs --keys-sha256 <hex> [--arch arm64|x64]
//                                     [--upstream host:port] [--skip-build]
//
// It writes config/personas.json (which is what turns the app into a personas build; see
// app/personas.main.ts), builds the production bundle, and runs electron-builder with a
// configuration derived from package.json's but with everything that ties the app to
// Signal replaced:
//
//   - its own appId and name, so installing it can never overwrite, or be mistaken by
//     macOS for, a real Signal Desktop in /Applications;
//   - no update feed (the app also refuses to self-update in personas mode);
//   - ad-hoc signing instead of Signal's signing script, and no notarization: there is
//     no Apple developer account, so testers open it once with right-click > Open;
//   - one architecture per .dmg: Apple Silicon (arm64, default) or Intel (x64). For x64 the
//     ZK engine is cross-compiled here (Rust target x86_64-apple-darwin);
//   - config/personas.json packed in.
//
// Output: release-personas/Signal-Personas-<version>-<arch>.dmg

import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT_DIR = 'release-personas';

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i === -1 ? undefined : process.argv[i + 1];
}

const keysSha256 = arg('keys-sha256');
const upstream = arg('upstream') ?? 'signalserver.umiacs.umd.edu:443';
const skipBuild = process.argv.includes('--skip-build');
const arch = arg('arch') ?? 'arm64';
if (arch !== 'arm64' && arch !== 'x64') {
  throw new Error('personas-package: --arch must be arm64 or x64');
}

if (process.platform !== 'darwin' || process.arch !== 'arm64') {
  throw new Error(
    'personas-package: build on an Apple Silicon Mac (it cross-compiles the Intel engine)'
  );
}
if (!keysSha256 || !/^[0-9a-f]{64}$/.test(keysSha256)) {
  throw new Error(
    'personas-package: pass --keys-sha256 <hex>, the pin printed by deploy/play/keys.sh. ' +
      'Without it every install would generate its own incompatible proving keys.'
  );
}

// 1. The personas build settings. Server parameters come from the committed example
//    (the test server's zkgroup params and trust root); the server and pin from the args.
const example = JSON.parse(readFileSync(join(ROOT, 'config/personas.example.json'), 'utf8'));
const personas = {
  ...example,
  upstream,
  upstreamTls: true,
  keysSha256,
};
const personasPath = join(ROOT, 'config/personas.json');
writeFileSync(personasPath, `${JSON.stringify(personas, null, 2)}\n`);
console.log(`personas-package: config/personas.json -> ${upstream}, keys ${keysSha256.slice(0, 12)}…`);

// Removed again at the end, success or not: left behind, it would quietly turn ordinary
// development runs (scripts/personas-run.sh) into personas builds.
process.on('exit', () => rmSync(personasPath, { force: true }));

const run = (cmd, args, env = {}) =>
  execFileSync(cmd, args, { cwd: ROOT, stdio: 'inherit', env: { ...process.env, ...env } });

// 2. The production bundle (same steps as `pnpm run build`, minus electron-builder).
if (!skipBuild) {
  run('pnpm', ['run', 'generate']);
  run('pnpm', ['run', 'build:rolldown:prod']);
}

// 2b. The ZK engine, rebuilt from the Rust workspace every time so a package can never
//     ship a stale one, and placed where packages/personas-engine/index.cjs looks for it
//     (personas-engine.<platform>-<arch>.node). Apple Silicon is the native build
//     (packages/personas-engine/build.sh); Intel is cross-compiled.
if (arch === 'arm64') {
  run(join(ROOT, 'packages/personas-engine/build.sh'), []);
}
if (arch === 'x64') {
  const rustDir = join(ROOT, '..');
  execFileSync(
    'cargo',
    ['build', '-p', 'personas-node', '--release', '--target', 'x86_64-apple-darwin'],
    // From the Rust workspace, so its rust-toolchain.toml (the pinned nightly) applies.
    { cwd: rustDir, stdio: 'inherit' }
  );
  execFileSync(
    'cp',
    [
      join(rustDir, 'target/x86_64-apple-darwin/release/libpersonas_node.dylib'),
      join(ROOT, 'packages/personas-engine/personas-engine.darwin-x64.node'),
    ],
    { stdio: 'inherit' }
  );
}

// 3. electron-builder, with the personas identity.
const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
const base = pkg.build;
// A distinct version per build (e.g. 8.23.0-alpha.1+personas.20261014-2125, UTC), shown in
// the file name and the About window, so testers and you can tell two builds apart. It is
// semver BUILD metadata (after "+"): Signal's version parser requires the prerelease part
// to stay `<channel>.<number>`, and accepts build metadata outside the prod channel.
const stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 13).replace('T', '-');
const version = `${pkg.version}+personas.${stamp}`;
const builderConfig = {
  ...base,
  appId: 'org.cryptopersonas.signal-personas',
  productName: 'Signal Personas',
  extraMetadata: {
    ...base.extraMetadata,
    version,
    productName: 'Signal Personas',
    environment: 'production',
  },
  directories: { ...base.directories, output: OUT_DIR },
  files: [...base.files, 'config/personas.json'],
  publish: null,
  mac: {
    ...base.mac,
    target: [{ target: 'dmg', arch: [arch] }],
    artifactName: 'Signal-Personas-${version}-${arch}.${ext}',
    publish: null,
    // Ad-hoc signature: required for the app to launch at all on Apple Silicon (the
    // afterPack fuse step rewrites the Electron binary), without an Apple identity.
    sign: undefined,
    identity: '-',
    // No notarization without a developer account, and the hardened runtime's library
    // validation would reject the ad-hoc signed native addons.
    hardenedRuntime: false,
    notarize: false,
  },
  dmg: { ...base.dmg, title: 'Signal Personas' },
};
delete builderConfig.mac.sign;
mkdirSync(join(ROOT, OUT_DIR), { recursive: true });
const configPath = join(ROOT, OUT_DIR, 'electron-builder.personas.json');
writeFileSync(configPath, `${JSON.stringify(builderConfig, null, 2)}\n`);

run(
  'pnpm',
  ['exec', 'electron-builder', '--mac', 'dmg', `--${arch}`, '--publish', 'never', '--config', configPath],
  { SIGNAL_ENV: 'production', NODE_OPTIONS: '--import=tsx' }
);

console.log(`personas-package: done -> ${OUT_DIR}/ (version ${version})`);
