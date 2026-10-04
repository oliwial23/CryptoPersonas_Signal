// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Track 1 (no Signal): two engines drive emit -> ingest and converge on identical
// roots; a ban poll flags the offending post everywhere. The Desktop-side analogue
// of the Rust replica e2e (`e2e_convergence_ban_and_flag`), proving the addon
// surface end to end with no transport involved.
//
// Usage: node converge.mjs <keyDir>
//   keyDir defaults to a shared scratch dir; the first run generates ~51MB of keys.

import { Engine } from '../index.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const keyDir = process.argv[2] ?? join(tmpdir(), 'personas-keys');
const BAN_OPTION = 0;

let failures = 0;
function check(label, cond) {
  const ok = Boolean(cond);
  console.log(`  ${ok ? 'PASS' : 'FAIL'}  ${label}`);
  if (!ok) {
    failures += 1;
  }
}

function ms(t0) {
  return `${Math.round(Number(process.hrtime.bigint() - t0) / 1e6)}ms`;
}

console.log(`personas-engine convergence test (keys: ${keyDir})`);
console.log('Building two member engines (first run generates keys — slow) ...');

// Same dataDir + deterministic seeds so both members share keys and the run
// reproduces. conversation must match for records to ingest.
const opts = { dataDir: keyDir, conversation: 'converge-test' };
const alice = new Engine({ ...opts, seed: 1 });
const bob = new Engine({ ...opts, seed: 2 });
const members = [alice, bob];

const deliverAll = emitted => {
  for (const m of members) {
    m.ingest(emitted.bytes, 0); // 0 => local-barrier cadence, driven by barrier()
  }
};

// (1) Both join; every replica ingests every join.
console.log('\n(1) Both members join.');
for (const m of members) {
  deliverAll(m.emitJoin());
}

// (2) alice posts under a persona.
console.log('(2) alice posts under a persona (real Groth16 proof) ...');
let t0 = process.hrtime.bigint();
const post = alice.emitPostPseudo('here is my hot take', 0xabcd);
console.log(`    proof-gen ${ms(t0)}; persona=${post.persona}; eh=${post.eh.slice(0, 12)}…`);
deliverAll(post);

check('alice renders the post', alice.render().some(l => l.includes('hot take')));
check('bob renders the post', bob.render().some(l => l.includes('hot take')));
check('fingerprints converge after post', alice.fingerprint() === bob.fingerprint());

// (3) bob opens a ban poll on the post; both vote to ban.
console.log('(3) bob opens a ban poll; both vote to ban ...');
const poll = bob.emitPoll('ban this persona?', ['ban', 'keep'], 'ban', post.eh);
deliverAll(poll);
t0 = process.hrtime.bigint();
const vote1 = alice.emitVote(poll.eh, BAN_OPTION);
const vote2 = bob.emitVote(poll.eh, BAN_OPTION);
console.log(`    two vote proofs ${ms(t0)}`);
deliverAll(vote1);
deliverAll(vote2);
check('fingerprints converge after votes', alice.fingerprint() === bob.fingerprint());

// (4) Every replica crosses a settlement barrier: the ban settles, the post flags.
console.log('(4) Both cross a settlement barrier (the ban bites) ...');
for (const m of members) {
  m.barrier();
}

const aliceFlagged = alice.log().some(e => e.body.includes('hot take') && e.flagged);
const bobFlagged = bob.log().some(e => e.body.includes('hot take') && e.flagged);
check('the offending post is flagged on alice', aliceFlagged);
check('the offending post is flagged on bob', bobFlagged);
check('post is NOT deleted (still present)', alice.log().some(e => e.body.includes('hot take')));
check('fingerprints converge after the ban settles', alice.fingerprint() === bob.fingerprint());

console.log('\nalice final view:');
for (const line of alice.render()) {
  console.log(`   ${line}`);
}

console.log(`\n${failures === 0 ? 'ALL CHECKS PASSED ✅' : `${failures} CHECK(S) FAILED ❌`}`);
process.exit(failures === 0 ? 0 : 1);
