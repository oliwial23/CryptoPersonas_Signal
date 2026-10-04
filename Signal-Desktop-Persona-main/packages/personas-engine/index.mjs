// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Loads the platform-specific napi-rs addon. N-API is ABI-stable, so the same
// binary loads under both standalone Node (the convergence test / benchmarks) and
// Electron. Only darwin-arm64 is built for the demo; add more `.node` files here to
// support other platforms.

import { createRequire } from 'node:module';
import { platform, arch } from 'node:process';

const require = createRequire(import.meta.url);
const binary = `personas-engine.${platform}-${arch}.node`;

let addon;
try {
  addon = require(`./${binary}`);
} catch (error) {
  throw new Error(
    `@signalapp/personas-engine: failed to load ${binary}. ` +
      'Rebuild it with `pnpm --filter @signalapp/personas-engine build` ' +
      `(needs the CryptoPersonas_Signal Rust workspace). Cause: ${error.message}`
  );
}

export const { Engine } = addon;
export default addon;
