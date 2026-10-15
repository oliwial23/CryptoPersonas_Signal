// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
// Late-join catch-up, through the addon surface Desktop uses: a member added after the
// group started posting takes in an admin's history (no message text), then sends and
// receives, and keeps working across a restart.
//
// Usage: node catchup.mjs <keyDir>

import { Engine } from '../index.mjs';
import { mkdtempSync, rmSync } from 'node:fs';
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

const work = mkdtempSync(join(tmpdir(), 'personas-catchup-'));
const opts = { dataDir: keyDir, conversation: 'catchup-test' };
const acct = n => n.toString(16).padStart(32, '0');
const admin = new Engine({ ...opts, seed: 1 });
const alice = new Engine({ ...opts, seed: 2 });
const deliver = (e, to) => to.map(m => m.ingest(e.bytes, 0).status);

console.log('(1) the group posts before the newcomer arrives');
deliver(admin.emitJoin(acct(1)), [alice]);
deliver(alice.emitJoin(acct(2)), [admin]);
const old = alice.emitPostAnon('an old secret');
deliver(old, [admin]);
deliver(admin.emitPostPseudo('earlier, pseudonymously', 5), [alice]);
admin.barrier();
alice.barrier();

console.log('(2) the newcomer takes in the admin\'s history');
const journal = join(work, 'bob.journal');
const bob = new Engine({ ...opts, seed: 3, journalPath: journal });
const history = admin.exportCatchUp();
check('the history carries no message text', !history.toString('latin1').includes('an old secret'));
check('every record is taken in', bob.importCatchUp(history) === admin.log().length);
check('a second copy adds nothing', bob.importCatchUp(history) === 0);
check('same state as the admin', bob.fingerprint() === admin.fingerprint());
check('old posts known, without their text', bob.logEntry(old.eh)?.body === '');

console.log('(3) and then sends and receives');
const everyone = [admin, alice];
check('its join is applied', deliver(bob.emitJoin(acct(3)), everyone).every(s => s === 'applied'));
check('its post is applied', deliver(bob.emitPostAnon('hi all'), everyone).every(s => s === 'applied'));
const welcome = alice.emitPostPseudo('welcome', 5);
deliver(welcome, [admin]);
check('it receives the others\' posts', deliver(welcome, [bob])[0] === 'applied');
check('all three agree', bob.fingerprint() === admin.fingerprint() && alice.fingerprint() === admin.fingerprint());

console.log('(4) across a restart');
const saved = bob.exportMemberState();
const bob2 = new Engine({ ...opts, seed: 4, memberState: saved, journalPath: journal });
check('the restored replica matches', bob2.fingerprint() === admin.fingerprint());
check('and its next post is applied', deliver(bob2.emitPostAnon('still here'), everyone).every(s => s === 'applied'));

rmSync(work, { recursive: true, force: true });
console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
