// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
// An admin's permanent ban, through the addon surface Desktop uses: one record, no
// poll, in effect at the next barrier.
//
// Usage: node ban.mjs <keyDir>

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

const opts = { dataDir: keyDir, conversation: 'ban-test' };
const acct = n => n.toString(16).padStart(32, '0');
const admin = new Engine({ ...opts, seed: 1 });
const alice = new Engine({ ...opts, seed: 2 });
const both = [admin, alice];
const deliver = (e, to) => to.map(m => m.ingest(e.bytes, 0).status);

deliver(admin.emitJoin(acct(1)), [alice]);
deliver(alice.emitJoin(acct(2)), [admin]);
const post = alice.emitPostPseudo('the offending post', 7);
deliver(post, [admin]);

const ban = admin.emitBan(post.eh);
check('a ban must come from an admin (the client checks)', admin.recordAccountClaim(ban.bytes)?.kind === 'ban');
check('it is applied', deliver(ban, [alice])[0] === 'applied');
check('no poll is opened', admin.renderPolls().length === 0);
both.forEach(m => m.barrier());
check('both agree', admin.fingerprint() === alice.fingerprint());
check('the post is flagged', admin.log().find(e => e.eh === post.eh)?.flagged === true);
while (alice.scanNeeded()) {
  alice.prepareScan();
  deliver(alice.commitScan(), both);
}
check('the author is banned after their scan', alice.isBanned() === true);

console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
