# @signalapp/personas-engine

The CryptoPersonas ZK engine as a Node/Electron native addon (napi-rs), wrapping
the transport-agnostic `Messenger` (a d3 `Replica` plus an optional `Member`) from
the `CryptoPersonas_Signal` Rust workspace.

**There is no Signal crypto here.** `emit*` produce CBOR record bytes carrying real
Groth16 proofs — the *plaintext* Signal-Desktop then encrypts and delivers over its
own libsignal. `ingest` verifies + folds a record that arrived over Desktop.
Recipient-anonymity (the shared phantom sender identity) is entirely a Desktop-side
concern; this engine only computes over record bytes.

## Usage

```js
import { Engine } from '@signalapp/personas-engine';

const engine = new Engine({ dataDir: '/path/to/keys' }); // first run generates ~51MB of keys
const join = engine.emitJoin();          // { bytes, eh, persona? }
const post = engine.emitPostPseudo('hello', 0xABCD);
engine.ingest(post.bytes, 0);            // { status: 'applied' }
engine.render();                         // ['~two-word: hello']
```

See `index.d.ts` for the full surface.

## Rebuilding the native binary

```sh
pnpm --filter @signalapp/personas-engine build
# or: ./build.sh   (set PERSONAS_RUST_DIR if the Rust workspace isn't a sibling)
```

Requires the pinned nightly toolchain (see `rust-toolchain.toml` in the Rust
workspace). N-API is ABI-stable, so one release binary loads under both standalone
Node and Electron. Only `darwin-arm64` is built for the demo.

## Heights / keys

The engine is instantiated at the production Merkle heights (32/32/32), so it must
use keys generated at those heights — `ensure_merkle_keys(dataDir)` handles that
(cached after the first, slow run). Share one `dataDir` across all members of a
group so they use identical keys.
