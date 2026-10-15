// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
// Proven joins, one per account, and the admin-approved reset, through the addon surface
// Desktop uses.
//
// Usage: node joins.mjs <keyDir>

import { Engine } from '../index.mjs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const keyDir = process.argv[2] ?? join(tmpdir(), 'personas-keys');
let failures = 0;
function check(label, cond) {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) {
    failures += 1;
  }
}

const opts = { dataDir: keyDir, conversation: 'joins-test' };
const ADMIN = '0000000000000000000000000000a001';
const ALICE = '0000000000000000000000000000a002';
const admin = new Engine({ ...opts, seed: 1 });
const alice = new Engine({ ...opts, seed: 2 });
const both = [admin, alice];
const deliver = (e, to) => to.map(m => m.ingest(e.bytes, 0).status);
const tick = () => both.forEach(m => m.barrier());

console.log('(1) proven joins, one per account');
const aj = alice.emitJoin(ALICE);
check('a join names its account', JSON.stringify(admin.recordAccountClaim(aj.bytes)) === JSON.stringify({ kind: 'join', account: ALICE }));
deliver(admin.emitJoin(ADMIN), both);
check('a fresh, proven join is applied', deliver(aj, both).every(s => s === 'applied'));
tick();
const impostor = new Engine({ ...opts, seed: 3 });
check('a second join for the same account is rejected', deliver(impostor.emitJoin(ALICE), [admin])[0] === 'rejected');
tick();

console.log('(2) a reset request carries a "not banned" proof');
deliver(alice.emitPostAnon('hello'), both);
let refused = false;
try {
  alice.proveNotBanned(ALICE);
} catch {
  refused = true;
}
check('refused until a full scan', refused);
for (let i = 0; i < 4; i += 1) tick();
while (alice.scanNeeded()) {
  alice.prepareScan();
  deliver(alice.commitScan(), both);
}
const proof = alice.proveNotBanned(ALICE);
check('the admin verifies it, for the right account', admin.verifyNotBanned(proof) === ALICE);
const stranger = new Engine({ ...opts, seed: 4 });
check('a replica without that tree refuses it', stranger.verifyNotBanned(proof) === null);

console.log('(3) the admin approves; alice re-joins once');
const approve = admin.emitRejoinApprove(ALICE);
check('an approval names its account', admin.recordAccountClaim(approve.bytes)?.kind === 'rejoin-approve');
deliver(approve, both);
check('counts: 1 join, 1 approved', JSON.stringify(alice.joinCounts(ALICE)) === JSON.stringify({ joins: 1, approved: 1 }));
tick();
alice.resetMember();
check('the reset member is not on the bulletin yet', !alice.memberOnBulletin());
check('its re-join is applied', deliver(alice.emitJoin(ALICE), both).every(s => s === 'applied'));
check('and it can post again', deliver(alice.emitPostAnon('back'), [admin])[0] === 'applied');
tick();
const third = new Engine({ ...opts, seed: 5 });
check('the approval is used up', deliver(third.emitJoin(ALICE), [admin])[0] === 'rejected');
check('converged', admin.fingerprint() === alice.fingerprint());

console.log(failures ? `\n${failures} CHECK(S) FAILED` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);
