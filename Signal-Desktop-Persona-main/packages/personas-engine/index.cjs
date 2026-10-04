// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// CommonJS entry: the Signal-Desktop preload/renderer bundle is emitted as CJS, so
// it reaches this addon through `require`. N-API is ABI-stable, so the same binary
// loads under both standalone Node and Electron.

const { platform, arch } = require('node:process');

const binary = `personas-engine.${platform}-${arch}.node`;

let addon;
try {
  // eslint-disable-next-line import/no-dynamic-require, global-require
  addon = require(`./${binary}`);
} catch (error) {
  throw new Error(
    `@signalapp/personas-engine: failed to load ${binary}. ` +
      'Rebuild it with `pnpm --filter @signalapp/personas-engine build` ' +
      `(needs the CryptoPersonas_Signal Rust workspace). Cause: ${error.message}`
  );
}

module.exports = addon;
