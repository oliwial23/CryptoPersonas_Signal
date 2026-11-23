# Vendored Sonobe (`folding-schemes`)

**Origin.** `github.com/hkailad/sonobe` @ `4d4fa08727bed55821c787d51daf46a9a1f27ecd`
(hkailad's fork of PSE Sonobe; the rev zk-callbacks `d661879` pins). Only the
`folding-schemes` crate is vendored. `benches/` and three `examples/` are kept because
`folding-schemes/Cargo.toml` names them by `../` path. The root `Cargo.toml` is a trimmed
copy of upstream's workspace manifest (one member, only the inherited dependencies).

**How it is consumed.** The personas root `Cargo.toml` `exclude`s this directory and
redirects the git source with

```toml
[patch."https://github.com/hkailad/sonobe"]
folding-schemes = { path = "third_party/sonobe/folding-schemes" }
```

so zk-callbacks (which pins the same URL and rev) and every personas crate resolve to
this copy. `Cargo.lock` has a single `folding-schemes` entry with no `source`.

**A path patch does not change the rev string.** Anything keyed on
`sonobe=4d4fa08` — the server's content-addressed params cache, via `DEP_REVS` in
`crates/personas-core/src/params.rs` — has to be bumped by hand whenever this copy changes
a circuit or the fold semantics. Without the bump, a server silently loads a stale
`nova_params.bin` and every fold proof fails.

## Running this crate's own tests

The crate has dev-dependencies the personas workspace doesn't (`ark-pallas`,
`ark-vesta`, the MNT curves, `criterion`, `pprof`), so its tests run in its own
workspace with its own `Cargo.lock` (seeded from the personas lock, so every `ark-*`
version matches the personas build):

```sh
CARGO_TARGET_DIR=target/sonobe \
  cargo test --release --manifest-path third_party/sonobe/Cargo.toml -p folding-schemes \
  folding::nova:: -- --skip decider --test-threads 4
```

Notes:
- `folding::nova::` also matches `folding::hypernova::`. The decider tests are very heavy:
  run all at once, they got the test process SIGKILLed on a 16 GB machine. Skip them, or
  run them one by one.
- `CARGO_TARGET_DIR=target/sonobe` puts the build under the personas `/target/`, which is
  already gitignored.

**Pristine baseline at `4d4fa08`** (without deciders, release): 14 passed, 5 failed.
All five failures are one pre-existing fork bug, not ours. The fork changed
`nova::VerifierParams` to a *derived* `CanonicalSerialize` (the whole struct, R1CS
included; personas relies on this to cache `nova_params.bin`), but left
`Nova::vp_deserialize_with_mode` reading only `cs_vp ‖ cf_cs_vp`. So the
serialize/deserialize round trip in `nova::tests::test_ivc_opt` fails with
`SerializationError(InvalidData)`, along with every test that calls it (`test_ivc` and
the four `zk::tests`). Personas never calls `vp_deserialize_with_mode`.

## Patch ledger

Every change to `folding-schemes/src` since the pristine copy, in commit order. See
`docs/FOLD_ITERATION_HIDING.md` for the construction and the security argument, and
`docs/FINDINGS.md` (O14–O19, D13) for the bug write-ups.

| # | Change | Why |
|---|---|---|
| 0 | (pristine copy, `src/` byte-identical to `4d4fa08`) | — |
| 1 | `Nova::vp_deserialize_with_mode` reads the derived `VerifierParams` encoding, then requires its R1CS to equal the circuit's | Pre-existing fork bug: the round trip failed with `InvalidData`, which broke `test_ivc_opt` and the 5 tests built on it. Not crypto. Baseline is now 19/19. |
| 2 | `nova/attacks.rs`: hand-built B1/B2/B3 attacks, asserting that they **succeed** | Proves the bugs are real on the unfixed code. The fix commit flips every assertion. |
| 3 | **B1** `Witness::check_shape_and_openings`; `RandomizedIVCProof::verify` takes `cs_pp`/`cf_cs_pp` and checks lengths plus `W'`→`U'` and `cf_W`→`cf_U` openings; `Nova::verify` checks all three openings through the new `CommitmentScheme::commit_with_verifier_params` (default: fail closed; Pedersen and IPA override it). **B3** `Witness::new` sets `rE = 0`; the `prove_step` blinding check no longer expects a nonzero incoming `rE`. **B2** base case: `z_i[k].conditional_enforce_equal(z_0[k], is_basecase)`. `attacks.rs` flipped to assert rejection. | Soundness (FINDINGS O14/O15/O16). `test_ivc`'s KZG case now asserts `NotSupported`: a KZG verifier key cannot recompute a vector commitment. |
| 4 | **C2** `Nova::randomize_initial_accumulators` (H = true only, i == 0 only, once): `(W_i,U_i)` and `(cf_W_i,cf_U_i)` start from `sample_witness_instance` pairs; private `randomized_init` flag. Circuit: the base output hashes the witnessed `U_i` (sponge vector selected before one hash) and reuses `H(cf_U_i)`; the native base step passes `cf_U_i: Some(..)`. `RandomizedIVCProof::new` refuses without the flag or at `i == 0`. Test builds assert openings and R1CS shape on every `prove_step`. New `nova/iterhide_tests.rs`; zk tests ported. | Iteration hiding: kills the `U.u`/`cf_U.u` 128-bit-sum leak and the `U_1 = U_⊥` tell (FINDINGS O19). Augmented R1CS −2,972 constraints (two constant hashes gone). |
| 5 | **C1** committed step counter `c = Poseidon(D_CTR, i, ρ)` (`STEP_COUNTER_DOMAIN = "personas/nova/step-counter/v1"`): `ρ` witness allocated next to `i`; `c_i`/`c_{i+1}` replace `i`/`i+1` in the instance hashes (the generic `hash(…, i, …)` signatures are unchanged, so `c` goes in the `i` slot and HyperNova and ProtoGalaxy are untouched). `Nova.rho` (sampled by `randomize_initial_accumulators`), `Nova::c()`, `IVCProof.rho`; `Nova::verify` recomputes `c`. `RandomizedIVCProof::verify` takes `c` instead of `i` and the `i == 0 → Ok` shortcut is removed. | Iteration hiding: the step count no longer appears in the proof's public input. Augmented R1CS +582 constraints / +583 witnesses (2 permutations + `ρ`). |
| 6 | **C4** `NIFS::prove_hiding` (H = true): fresh `r_T`, `cmT = Com(T, r_T)`, `rE' = rE₁ + r·r_T + r²·rE₂` (`fold_witness_with_rT`, which `fold_witness` now calls with `r_T = 0`). Used only by the two folds in `RandomizedIVCProof::new`. | The shipped `π`/`π′` were `Com(T, 0)`, deterministic in the witnesses, while the D.4 / Lemma 9 hiding argument assumes hiding commitments. No R1CS or verifier change. `prove_step` keeps `r_T = 0` (C2's base case relies on it). |
| 7 | Nova `decider`, `decider_circuits`, `decider_eth` and HyperNova `decider_eth` behind the off-by-default `deciders` feature (`folding-schemes/Cargo.toml`). `decider_eth_circuit` stays compiled. | Fork hygiene: the deciders verify the upstream fold semantics (bare `i`, `U_⊥` base case) and were not updated, so they must not be reachable by default. zk-callbacks and personas use none of them. |
| 8 | `nova::decider_eth_circuit`: its `TryFrom<Nova> for DeciderEthCircuit` and its test module behind `deciders` too (the module stays compiled for `WitnessVar`; `allow(unused_imports)` without the feature). | That test (`test_decider_circuit`) is compiled by default and failed under the fork: the stale decider circuit hashes the bare `i`. |
