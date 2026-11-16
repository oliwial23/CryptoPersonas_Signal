# Precomputed tickets: a walkthrough (server-based implementation)

Runs the validation server against an in-process mock chat and exercises the
precomputed-ticket (Privacy Pass) commands. From the repository root, after
`cargo build --release --bin server --bin personas`.

Terminal 1, the server (a fresh data directory each run):

```sh
rm -rf /tmp/pp-test
PERSONAS_PROFILE=local PERSONAS_BIND=127.0.0.1:3095 PERSONAS_DATA_DIR=/tmp/pp-test ./target/release/server
```

Terminal 2, a client:

```sh
P=(--transport signal --api http://127.0.0.1:3095 --data-dir /tmp/pp-test-client)
./target/release/personas "${P[@]}" join

# Each redemption spends one ticket, requested (and stashed locally) beforehand.
./target/release/personas "${P[@]}" priv-pass-request

# A pseudonymous post paid for with a precomputed ticket instead of a fresh proof.
./target/release/personas "${P[@]}" priv-pass-pseudo-post -m "hi" -g "1"
```

The other redemption is `priv-pass-post` (no persona). A ticket buys only a post:
redeeming one for a badge or reputation would let any holder grant themselves either.
