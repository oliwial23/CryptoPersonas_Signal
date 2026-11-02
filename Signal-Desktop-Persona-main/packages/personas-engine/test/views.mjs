// Multi-instance test of view checking and relays (SERVERLESS_PROTOCOL.md §5.5).
//
// Four members, each a separate Node process running this package's native engine at
// production circuit sizes, on a shared barrier schedule. This process plays Signal: it
// stamps each message with a timestamp and delivers it, to everyone or, to simulate a
// misbehaving service, to only some members. Members handle messages as Signal Desktop
// does (personasEngine.preload.ts): ingest a record, or a relayed record at the barrier
// the relay names, then send any relays the engine asks for.
//
//   node test/views.mjs <keys dir> [barrier period ms]
//
// The first run in an empty keys dir generates the ~51 MB key bundle (minutes).
// Exits non-zero on the first failed check.

import { fork } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const RECORD = 'PZR2:';
const RELAY = 'PZY2:';

// --- A member ---------------------------------------------------------------------------

if (process.argv[2] === 'member') {
  const { Engine } = require('../index.cjs');
  const [, , , name, dataDir, anchor, period] = process.argv;
  const engine = new Engine({
    dataDir,
    viewChecks: true,
    conversation: 'views-test',
    heartbeatAnchorMs: Number(anchor),
    heartbeatPeriodMs: Number(period),
  });
  const ticker = setInterval(() => engine.tick(Date.now()), 50);

  const handlers = {
    join: () => engine.emitJoin(randomBytes(16).toString('hex')),
    post: ({ body }) => engine.emitPostAnon(body),
    // Same handling as ingestRecordForTimeline + relayAndCheckViews in Desktop.
    deliver: ({ body, at }) => {
      engine.tick(Date.now());
      const status = body.startsWith(RELAY)
        ? ingestRelay(body.slice(RELAY.length), at)
        : engine.ingest(Buffer.from(body.slice(RECORD.length), 'base64'), at);
      const relays = engine
        .takeRelays()
        .map(r => `${RELAY}${r.barrier}:${Buffer.from(r.record).toString('base64')}`);
      return { status: status.status, relays };
    },
    state: ({ eh }) => {
      engine.tick(Date.now());
      return {
        report: engine.viewReport(),
        fingerprint: engine.fingerprint(),
        holds: eh ? engine.logEntry(eh) != null : undefined,
      };
    },
  };
  function ingestRelay(rest, at) {
    const colon = rest.indexOf(':');
    const barrier = Number(rest.slice(0, colon));
    return engine.ingestRelayed(Buffer.from(rest.slice(colon + 1), 'base64'), barrier, at);
  }

  process.on('message', ({ id, op, ...args }) => {
    if (op === 'stop') {
      clearInterval(ticker);
      process.exit(0);
    }
    try {
      let result = handlers[op](args);
      if (op === 'join' || op === 'post') {
        result = { body: RECORD + Buffer.from(result.bytes).toString('base64'), eh: result.eh };
      }
      process.send({ id, result });
    } catch (error) {
      process.send({ id, error: String(error) });
    }
  });
  process.send({ ready: name });
}

// --- Signal, and the checks -------------------------------------------------------------

else {
  const dataDir = process.argv[2];
  const period = Number(process.argv[3] ?? 1500);
  if (!dataDir) {
    console.error('usage: node test/views.mjs <keys dir> [barrier period ms]');
    process.exit(2);
  }
  const { Engine } = require('../index.cjs');
  // Make sure the keys exist before the members race to generate them.
  new Engine({ dataDir, member: false });

  const anchor = Date.now();
  const self = fileURLToPath(import.meta.url);
  const members = {};
  let nextId = 0;
  const pending = new Map();

  async function start(name) {
    const child = fork(self, ['member', name, dataDir, String(anchor), String(period)]);
    child.on('message', msg => {
      if (msg.ready) return;
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(`${name}: ${msg.error}`)) : resolve(msg.result);
    });
    await new Promise(resolve => child.once('message', resolve));
    members[name] = child;
  }
  const call = (name, op, args = {}) =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, { resolve, reject });
      members[name].send({ id, op, ...args });
    });

  let relaysSent = 0;
  // Deliver one message, stamped now, to `to`; then deliver every relay it provokes, to
  // everyone (Signal itself is only selective when the test says so).
  async function deliver(body, to = Object.keys(members)) {
    const at = Date.now();
    const relays = [];
    for (const name of to) {
      const { relays: more } = await call(name, 'deliver', { body, at });
      relays.push(...more);
    }
    for (const relay of relays) {
      relaysSent += 1;
      await deliver(relay);
    }
  }
  async function act(name, op, body, to) {
    const emitted = await call(name, op, { body });
    await deliver(emitted.body, to);
    return emitted.eh;
  }
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const barriers = n => sleep(n * period);
  function check(ok, what) {
    console.log(`${ok ? 'ok  ' : 'FAIL'}  ${what}`);
    if (!ok) {
      for (const child of Object.values(members)) child.send({ op: 'stop' });
      process.exit(1);
    }
  }
  const states = async (names, eh) =>
    Object.fromEntries(
      await Promise.all(names.map(async n => [n, await call(n, 'state', { eh })]))
    );

  await Promise.all(['A', 'B', 'C'].map(start));
  console.log(`members A, B, C up; barrier period ${period} ms`);

  // 1. Normal operation: everything reaches everyone. No false alarms, no relays.
  for (const name of ['A', 'B', 'C']) await act(name, 'join');
  for (let round = 0; round < 6; round++) {
    await act('ABC'[round % 3], 'post', `round ${round}`);
    await barriers(0.6);
  }
  await barriers(3);
  for (const name of ['A', 'B', 'C']) await act(name, 'post', `checked by ${name}`);
  await barriers(3);
  let s = await states(['A', 'B', 'C']);
  check(
    Object.values(s).every(x => !x.report.diverged && x.report.agreeing > 0),
    `normal: every member's views agree (${Object.values(s).map(x => x.report.agreeing).join('/')} agreeing claims)`
  );
  check(relaysSent === 0, 'normal: nothing was relayed');
  check(new Set(Object.values(s).map(x => x.fingerprint)).size === 1, 'normal: identical state');

  // 2. Signal withholds A's post from C. The next records expose it, A and B relay the
  //    post, and C catches up.
  const hidden = await act('A', 'post', 'not for C', ['A', 'B']);
  await barriers(3);
  await act('B', 'post', 'after the split (B)');
  await act('C', 'post', 'after the split (C)');
  s = await states(['A', 'B', 'C'], hidden);
  check(relaysSent > 0, `split: views disagreed and ${relaysSent} record(s) were relayed`);
  check(s.C.holds, 'split: C received the withheld post by relay');
  check(new Set(Object.values(s).map(x => x.fingerprint)).size === 1, 'split: identical state again');
  const relaysAfterSplit = relaysSent;
  await barriers(11); // older mismatches leave the 10-barrier window
  for (const name of ['A', 'B', 'C']) await act(name, 'post', `healed (${name})`);
  await barriers(3);
  s = await states(['A', 'B', 'C']);
  check(
    Object.values(s).every(x => !x.report.diverged),
    'split: after healing, every member sees agreement again'
  );
  check(relaysSent === relaysAfterSplit, 'split: nothing more was relayed after healing');

  // 3. Signal withholds a JOIN from C. Members detect it, but a join is accepted only
  //    because of who sent it, so nobody relays it and C stays diverged.
  await start('D');
  await act('D', 'join', undefined, ['A', 'B', 'D']);
  await barriers(3);
  await act('A', 'post', 'after the hidden join');
  await barriers(1);
  s = await states(['A', 'C']);
  check(s.C.report.diverged, 'hidden join: C detects that its view differs');
  check(s.A.fingerprint !== s.C.fingerprint, 'hidden join: not repaired by relays (by design)');

  for (const child of Object.values(members)) child.send({ op: 'stop' });
  console.log('all checks passed');
}
