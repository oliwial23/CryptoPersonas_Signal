# Phantom-identity proofs (recipient-anonymity, libsignal level)

Standalone, no-server, no-GUI proofs of the Phase 5 anonymity mechanism: every member
sends persona posts under **one shared phantom sender identity**, so a recipient — even
an instrumented member — cannot tell which member authored a post. These run directly
against the Desktop copy of `@signalapp/libsignal-client`, independent of the app.

```sh
# needs the repo's pinned Node (24.17.0). From the Signal-Desktop root:
node personas-proofs/phantom-gate.mjs         # → GATE PASSED
node personas-proofs/phantom-gate-multi.mjs   # → MULTI-RECIPIENT GATE PASSED
```

- **`phantom-gate.mjs`** — single-recipient (`sealedSenderEncrypt`). Two senders become
  byte-identical to a receiver: same sender UUID/device/identity-key and a
  byte-identical sender certificate. Also proves the trust-root injection (the phantom
  cert validates only against the added phantom root) and that a member cannot forge
  under the phantom cert with their own identity.
- **`phantom-gate-multi.mjs`** — the real Desktop group-send API
  (`sealedSenderMultiRecipientEncrypt` over real sessions built via `processPreKeyBundle`).
  Proves the two non-obvious contracts the send splice depends on: the passed identity
  store's key (the phantom) — not the session's embedded identity — drives the
  sealed-sender auth; and the identity store must know each recipient's identity
  (recipient info otherwise comes from the session). A forgery is rejected on decrypt
  with *"sender certificate key does not match authentication tag."*

The production realization of these is in `ts/services/personasPhantom.preload.ts` and
the `encryptForSenderKey` splice in `ts/util/sendToGroup.preload.ts`. See
`../PERSONAS_DEMO.md`.
