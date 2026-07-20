# d1 — the serverless Merkle bulletin (external-review package)

**Status:** implemented in `crates/personas-bulletin/src/merkle/`; 18 native/circuit
property tests + 2 end-to-end Groth16 tests green. **Not yet externally reviewed** —
this document is the review package. It states what was built, the security claims,
the assumptions a reviewer must validate, and what is deliberately deferred.

This is the crypto-review gate called out in the plan
(`take-a-look-at-shimmying-dolphin.md`, workstream d1) and the structural fix for
[FINDINGS O10](FINDINGS.md). Read [`docs/SERVERLESS_PROTOCOL.md`](SERVERLESS_PROTOCOL.md)
first for the protocol context; this doc is the implementation's security argument.

---

## 1. What it is

Serverless mode has no trusted signer, so the centralized bulletins — which prove
membership by knowledge of a **server signature** over each entry — do not apply.
d1 replaces them with **Merkle trees** whose **root** every replica recomputes from
the same ordered log, implemented against zk-callbacks' *public* bulletin traits.
It does **not** fork the upstream `impls/decentralized/ds` stub (which is empty).

| File | Contents |
|---|---|
| `merkle/tree.rs` | Fixed-height append-only Poseidon Merkle tree (`IncrementalMerkleTree`) + native witness (`MerklePath`) + native `compute_root`. |
| `merkle/gadget.rs` | In-circuit path verification (`enforce_merkle_membership`) and `MerklePathVar`. |
| `merkle/obj.rs` | `MerkleObjStore` → `PublicUserBul`/`UserBul`/`JoinableBulletin` (the object/user bulletin). |
| `merkle/callback.rs` | `MerkleCallbackStore` → `PublicCallbackBul`/`CallbackBul`: a called-ticket **membership** tree + a sorted-range **nonmembership** tree. |
| `merkle/params.rs` | Merkle-mode Groth16 key generation (`generate_merkle_server_keys`) + the end-to-end SNARK tests. |

All hashing is `Poseidon<2>` (zk-callbacks' `impls::hash::Poseidon`), identical to
every other commitment in the system. `Com`/`Nul`/`Time` are all `F` (BN254 scalar).

### Data structures

- **Object tree** (user bulletin): leaves are object commitments, held in a
  `BTreeMap` **sorted by commitment** and rebuilt over that order, so the root
  commits to the *set* of registrations, not their arrival order (like the
  nonmembership tree below). `MembershipWitness = MerklePath` (leaf index +
  `HEIGHT` siblings), `MembershipPub = root` (`F`). The in-circuit gadget is
  unchanged — it proves a path to *somewhere* in the tree — so sorted placement
  costs nothing in the circuit; it is purely a native construction choice, and it
  is what lets the replica engine (d3) converge without a per-record total order.
- **Callback membership tree** (called tickets): leaves are `H(tik, arg, time)` —
  matching the reference store's signed hash. Append-only. Used by a scan to
  *absorb* a ban/reputation callback.
- **Callback nonmembership tree** (sorted ranges): leaves are `H(lo, hi, epoch)`,
  one per complement range of the called set, **rebuilt every epoch**. Used by a
  scan to prove a ticket was *not* called. `NonMembershipWitness = RangeWitness`
  (`lo, hi, epoch, MerklePath`), `NonMembershipPub = root`.

The range partition, the ticket domain `[0, (p-1)/2 - 1)`, and the `lo <= tik < hi`
check are copied verbatim from the reference `SigRangeStore` — the only thing that
changed is the *trust root* (a Merkle root the verifier recomputes, in place of a
server signature).

---

## 2. The core security claim (the O10 fix)

[O10](FINDINGS.md#o10-a-called-back-callback-a-ban-can-be-evaded-forever-by-replaying-a-stale-nonmembership-range):
the scan circuit proves a *signed* nonmembership range but never binds its epoch to
the public `cur_time`, so after a ban a member replays a **pre-ban range** and never
absorbs the callback. The signed store cannot fix this itself — the signature
verifies against a **stable key** the circuit bakes in as a **constant**, so a stale
range still verifies.

**The Merkle store closes O10 by construction, not by adding an in-circuit
`epoch == cur_time` check.** The argument, in three steps:

1. **The public data is a root, so it cannot be a circuit constant.** A root changes
   on every append (object tree) or every epoch (nonmembership tree). Baking it in
   would pin the proving key to one tree. So Merkle-mode key generation passes
   `memb_data = None` (→ `bul_memb_is_const = false`, `interaction.rs:523`) and the
   scan uses `is_memb_data_const = is_nmemb_data_const = false`
   (`get_extra_pubdata_for_scan` hardcodes `true`; `merkle_scan_pubdata` sets both
   `false`). The circuit then allocates every root as a **public input**
   (`scan.rs:267-284`) and `PubScanArgs::to_field_elements` **includes** them in the
   public-input vector (`scan.rs:186-199`).

2. **The verifier pins the current root.** Each replica recomputes the tree from its
   own copy of the ordered log and verifies the proof against **the root it computed
   itself**. A stale nonmembership range hashes up to a **past** root; there is no
   current root it matches, so the proof does not verify. The epoch is also folded
   into every range leaf (`H(lo, hi, epoch)`), guaranteeing distinct epochs yield
   distinct roots even under an unchanged partition.

3. **Monotone vs. anti-monotone decides the buffering policy.** Object membership
   and called-ticket membership are **monotone**: a leaf, once in, stays in (the
   object set only grows, and the called set only grows), so a witness against a
   slightly stale root is still valid history under a newer root — a replica may
   accept membership proofs against a **buffer of recent roots**. Callback
   **non**membership is **anti-monotone** (a ticket becomes a member the instant it
   is called), so it must pin the **current epoch's root only, with no
   grace/buffer** — that is precisely O10. Rewind of the object tree is blocked not
   by the root but by the nullifier set (`has_never_received_nul`): the first record
   to reveal a nullifier registers its successor, and any later reveal of the same
   nullifier is refused (first-reveal-wins), which is what stops a member forking
   their state from an old object.

`merkle/callback.rs::tests::nmemb_gadget_rejects_stale_range_after_ban` reproduces
the exact O10 replay (grab a range, ban the ticket, advance the epoch, replay) and
shows the stale range **fails the in-circuit check** against the current root.
`end_to_end_scan_nonmembership_proof_merkle_mode` shows an honest nonmembership scan
**verifies** as a real Groth16 proof.

> **Service mode still owes the upstream fix.** This closes O10 *for serverless
> only*. As-a-service deployments still verify against a baked constant key and must
> get the upstream circuit change (`witness.epoch == cur_time` + per-epoch key
> rotation). d1 does not touch that path.

---

## 3. Assumptions a reviewer must validate

1. **Poseidon collision resistance** (standard Merkle argument). Membership/
   nonmembership soundness reduces to: a leaf not in the tree cannot be hashed up to
   the root without a second preimage. The gadget does **not** bind a leaf to a
   specific index — any valid path proves the leaf is *somewhere* in the tree, which
   is what set membership requires.

2. **Ticket domain for `is_cmp_unchecked`.** The range check uses
   `FpVar::is_cmp_unchecked`, which compares field elements as integers **without a
   range check** and is only sound when the operands sit in the lower field half
   `[0, (p-1)/2)`. The complement partition is built inside that domain (top bound
   `MODULUS_MINUS_ONE_DIV_TWO - 1`). **This is the identical assumption the reference
   `SigRangeStore` already relies on** — d1 inherits it unchanged; it is not a new
   assumption, but a reviewer should confirm the ticket value itself is constrained
   to the lower half upstream (in `FakeSigPubkey`/scan witness derivation), since a
   ticket in the upper half could otherwise skew the comparison.

3. **Nonmembership soundness rests on verifier-side root computation, not on
   in-circuit sortedness.** The range tree does **not** prove its ranges are sorted
   or gap-free in-circuit. It does not need to: the prover cannot choose the tree —
   the verifier (replica) recomputes the root from *its own* called set, so only the
   honest complement ranges hash to the pinned root. This mirrors how the signed
   store's signature restricts the prover to server-issued ranges; here the root
   pinning restricts the prover to replica-computed ranges. **A reviewer should
   confirm this framing holds in the replica engine (d3): the security depends on
   every replica pinning a root it derived itself, never a root taken from a
   proof or a peer.**

4. **The `is_memb_data_const = false` path is now load-bearing.** Personas has
   always used `true` (baked keys), so the `false` branches in `interaction.rs`
   (public-input membership) and `scan.rs` (public-input roots) were previously
   unexercised by this codebase. The two end-to-end tests exercise them through a
   real Groth16 setup→prove→verify. A reviewer should still eyeball those upstream
   branches for the public-input ordering (the tests would catch a mismatch, but the
   argument should be explicit).

5. **Determinism across replicas.** Convergence requires every replica to build a
   byte-identical tree from the same set of records. The **object tree** and the
   **nonmembership tree** are now both **order-independent** — each sorts and
   rebuilds, so their roots are pure functions of the (object / range) set. The
   **called-ticket** membership tree is still append-order-sensitive, but its
   appends are generated by the replica itself at settlement, so the ordered log
   never touches it directly — d3 fixes that order deterministically (ascending
   `eh`) so a barrier that settles two tickets cannot fork.
   `JoinableBulletin::join_bul` takes the nullifier as **data** (the reference
   samples it randomly — non-deterministic and unusable here). A reviewer should
   confirm the object store's sorted rebuild is deterministic (`BTreeMap` iteration
   order over `F` keys) and that first-reveal-wins on the nullifier set is what
   arbitrates a double-spend — not any tree property.

---

## 4. Test coverage

Native + constraint-satisfiability (fast, always run):

- `tree`: paths recompute the root; appends move the root; stale paths reach old
  roots (the monotone-history property); tamper (leaf/sibling/index) breaks the path.
- `gadget`: accepts a real member (satisfied CS, matches native root); rejects a
  non-member (unsatisfiable if forced true); rejects a stale root against a current
  path.
- `obj`: membership data round-trips; `verify_in` matches stored nul/cb-list;
  nullifier set blocks replay; joins are deterministic across two replicas.
- `callback`: ranges partition the complement; called tickets have membership
  witnesses; nonmembership gadget accepts a nonmember; **rejects a stale range after
  a ban (O10)**; rejects out-of-range; two replicas converge on both roots.

End-to-end real Groth16 (`#[ignore]`, run with
`cargo test -p personas-bulletin --release -- --ignored merkle::params`):

- `end_to_end_standard_proof_merkle_mode`: a standard post proves object membership
  against the root as a **public input** and verifies; a tampered root does **not**.
- `end_to_end_scan_nonmembership_proof_merkle_mode`: a scan of an uncalled callback
  proves **nonmembership** against the range root inside a real scan proof, and
  verifies — the O10 gadget, end to end.

**Coverage gaps a reviewer should note:** no end-to-end test yet for (a) a scan that
*absorbs* a called ticket (membership branch of `enforce_memb_nmemb` in a full
proof — the native path is tested), (b) the buffered-root acceptance window for
monotone membership (it is argued, not yet wired), or (c) multi-callback scans
(`N > 1`).

---

## 5. Deliberately deferred (not in d1)

- **Nova folding keys for Merkle mode.** Serverless defaults folding **off** (locked
  decision; [D8](FINDINGS.md#d8-the-fold-size-menu-is-a-closed-compile-time-set-not-an-arbitrary-runtime-n)),
  so only Groth16 key sets are built. A Merkle `FoldingScan`/`Nova` type set is a
  later item if folding is ever switched on serverless.
- **Replica root-pinning wiring (d3).** d1 provides the stores, gadgets, and keys;
  the replica engine that ingests the ordered log, maintains the trees, and pins the
  current/buffered roots at verify time is d3. Claim 3 above is only as strong as
  that engine.
- **Disk-cache integration.** `MERKLE_BULLETIN_MODE` is defined for the params cache
  key but the server/replica cache is not yet wired to Merkle keys (it is keyed to
  the central store today).
- **The pre-existing client scan bug** ([O2](FINDINGS.md#o2-client-scan-answers-one-callback-and-interacting-mid-sweep-panics))
  is unchanged.

---

## 6. Reviewer checklist (quick)

- [ ] Poseidon domain/params match the rest of the system (they use the same
      `Poseidon<2>`). Confirm 2-to-1 compression order `(left, right)` is consistent
      native vs. circuit.
- [ ] Ticket values are constrained to `[0, (p-1)/2)` upstream (assumption 2).
- [ ] Replica derives every pinned root itself; never trusts a root from a proof or
      peer (assumption 3, enforced in d3).
- [ ] Membership uses a buffered recent root; nonmembership uses the current epoch
      root only (claim 3).
- [ ] Public-input ordering for the `is_*_data_const = false` branches
      (assumption 4).
- [ ] `join_bul` nullifier is supplied as deterministic data by every replica
      (assumption 5).
