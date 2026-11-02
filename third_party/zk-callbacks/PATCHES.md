# zk-callbacks (vendored)

Vendored from https://github.com/hkailad/callbacks at rev `d6618793ce34cdb2fb987b1d6569f0f23f369d3e`
(the rev the workspace pins), wired in with `[patch."https://github.com/hkailad/callbacks.git"]`
in the root `Cargo.toml`. Only `src/`, `zk-object/` and `circom-poseidon/` are copied; the
nested `workspace` line was dropped from `Cargo.toml`.

## Patches

1. `src/util.rs` — `gen_poseidon_params` caches its result per (field type, rate,
   optimized_for_weights). The derivation itself (`derive_poseidon_params`) is unchanged; it
   used to run on every hash, native and in-circuit, and dominated proving and replica time.
   Returned values are identical, so keys, proofs and roots are unchanged.
