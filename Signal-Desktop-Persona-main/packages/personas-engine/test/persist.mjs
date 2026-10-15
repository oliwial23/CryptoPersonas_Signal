// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
// Restart persistence and the two-step scan, through the addon surface Desktop uses:
// a member saved after an emit and restored from that state plus its record journal
// comes back as itself (same replica, same pseudonym, peers accept its next post); a
// prepared scan blocks other emits, leaves the saved state at the pre-scan object, and
// commits into a record peers accept.
//
// Usage: node persist.mjs <keyDir>

import { Engine } from '../index.mjs';
import { appendFileSync, copyFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const keyDir = process.argv[2] ?? join(tmpdir(), 'personas-keys');
const work = mkdtempSync(join(tmpdir(), 'personas-persist-'));
let failures = 0;
function check(label, cond) {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${label}`);
  if (!cond) {
    failures += 1;
  }
}

const opts = { dataDir: keyDir, conversation: 'persist-test' };
const journalA = join(work, 'alice.journal');
const journalB = join(work, 'bob.journal');
const alice = new Engine({ ...opts, seed: 1, journalPath: journalA });
const bob = new Engine({ ...opts, seed: 2, journalPath: journalB });

const deliver = (emitted, to) => to.map(m => m.ingest(emitted.bytes, 0).status);

console.log('(1) join, post, save, restart');
for (const m of [alice, bob]) {
  deliver(m.emitJoin(), [alice, bob]);
}
const first = alice.emitPostPseudo('before the restart', 0x51);
const saved = alice.exportMemberState(); // saved BEFORE the post is delivered
deliver(first, [alice, bob]);

const alice2 = new Engine({ ...opts, seed: 3, memberState: saved, journalPath: journalA });
check('restored replica matches the peer', alice2.fingerprint() === bob.fingerprint());
check('restored member is on the bulletin (no new join needed)', alice2.memberOnBulletin());

const second = alice2.emitPostPseudo('after the restart', 0x51);
check('same pseudonym after the restart', second.persona === first.persona);
check('peer accepts the restored member’s post', deliver(second, [bob])[0] === 'applied');
check('still converged', alice2.fingerprint() === bob.fingerprint());

console.log('(2) the two-step scan');
const beforeScan = alice2.exportMemberState();
alice2.prepareScan();
let blocked = false;
try {
  alice2.emitPostAnon('should be refused');
} catch {
  blocked = true;
}
check('other emits are refused while a scan is prepared', blocked);
check(
  'saved state stays at the pre-scan object',
  Buffer.compare(alice2.exportMemberState(), beforeScan) === 0
);
check('prepared scan is still valid', alice2.scanStillValid());
alice2.discardScan();
check(
  'discard restores the pre-scan object',
  Buffer.compare(alice2.exportMemberState(), beforeScan) === 0
);
alice2.prepareScan();
const scan = alice2.commitScan();
check('peer accepts the committed scan', deliver(scan, [bob])[0] === 'applied');
let discardRefused = false;
try {
  alice2.discardScan();
} catch {
  discardRefused = true;
}
check('a committed scan cannot be discarded', discardRefused);
check('converged after the scan', alice2.fingerprint() === bob.fingerprint());

console.log('(2b) a badge arrives through the scans a post runs (no manual scan)');
// The send path's drain: scan until nothing is left to absorb, progress measured by the
// sweep (never by the outstanding count, which only moves when a sweep ends).
function drain(m) {
  let scans = 0;
  let ok = true;
  while (m.scanNeeded() && scans < 20) {
    const before = m.isScanning() ? m.sweepRemaining() : Infinity;
    m.prepareScan();
    deliver(m.commitScan(), [bob]);
    scans += 1;
    const after = m.isScanning() ? m.sweepRemaining() : 0;
    ok &&= after < before;
  }
  return { scans, ok };
}
// Section (2)'s single scan left a sweep half done, which blocks every other action.
const finished = drain(alice2);
check(`the half-done sweep is finished (${finished.scans} scans)`, finished.ok && !alice2.isScanning());
// alice2 asks for a badge, bob approves it.
const request = alice2.emitBadgeRequest(2);
deliver(request, [alice2, bob]);
check('no scan needed before anything is invoked', !alice2.scanNeeded());
const approve = bob.emitBadgeApprove(request.eh, 2);
deliver(approve, [alice2, bob]);
for (const m of [alice2, bob]) {
  m.barrier(); // the approval settles at the next barrier
}
check('the approval makes a scan needed', alice2.scanNeeded());
const { scans, ok: progressOk } = drain(alice2);
check(`every scan advanced the sweep (${scans} scans)`, progressOk && scans > 1);
check('the badge is in the object', alice2.getBadges().includes('Student'));
let posted = true;
try {
  deliver(alice2.emitPostAnon('with my badge'), [bob]);
} catch {
  posted = false;
}
check('and she can post right after', posted);
check('converged', alice2.fingerprint() === bob.fingerprint());

console.log('(3) journals restore on their own, torn tail included');
const bob2 = new Engine({ ...opts, seed: 4, member: false, journalPath: journalB });
check('peer journal restores the same replica', bob2.fingerprint() === bob.fingerprint());
const torn = join(work, 'torn.journal');
copyFileSync(journalB, torn);
appendFileSync(torn, Buffer.from([1, 0, 0, 0, 0, 0, 0, 0, 200, 0, 0, 0, 7, 7]));
const bob3 = new Engine({ ...opts, seed: 5, member: false, journalPath: torn });
check('a torn final entry is ignored', bob3.fingerprint() === bob.fingerprint());

rmSync(work, { recursive: true, force: true });
console.log(failures ? `\n${failures} CHECK(S) FAILED` : '\nALL CHECKS PASSED');
process.exit(failures ? 1 : 0);
