// Personas member directory: how demo clients find each other without CDSI.
//
// libsignal-net's localTestServer mode has no contact discovery, so each client publishes
// {aci, pni, e164, name, profileKey} here after registering and polls the list to seed
// its contacts. It replaces the shared roster folder, which only worked on one machine.
//
//   GET  /personas/directory            -> [entry, ...]   (only what the caller may see)
//        header x-personas-household: <household secret>   (optional)
//   GET  /personas/directory/number/<e164> -> {taken: bool}
//   PUT  /personas/directory/<aci>      <- {pni?, e164, name, profileKey?}
//        header x-personas-directory-secret: <random per-install secret>
//        header x-personas-household: <household secret>   (optional)
//        header x-personas-directory-public: <DIRECTORY_PUBLIC_TOKEN>   (optional)
//
// WHO SEES WHOM. A tester sees only
//   - PUBLIC entries: the browser members (alice, bob, carol, ...). An entry is public
//     only if its PUT carried the server's DIRECTORY_PUBLIC_TOKEN, which only the member
//     containers are given (compose.yml);
//   - its own HOUSEHOLD: the main account and the extra members opened from it on the
//     same Mac, which share a random secret kept there (app/user_config.main.ts). The
//     server keeps only its hash.
// Nobody else's name, number or profile key is handed out. A new install checks that its
// number is free with /number/<e164>, which says nothing else about the entry.
//
// First writer owns an entry: the hash of the secret sent with the first PUT is kept,
// and later PUTs for that aci must present the same secret. That stops one member from
// renaming or redirecting another; it is not authentication of the Signal account.
//
// ACTIVITY. Clients re-publish every few minutes while running, so `updatedAt` doubles as
// a heartbeat:
//   - entries silent for ACTIVE_WINDOW (default 1 h) are left out of the list, so closed
//     or uninstalled apps stop showing up as contacts for new members;
//   - an entry silent for TAKEOVER_AFTER (default 24 h) may be claimed by a new install of
//     the same account (a reset or reinstall that kept its number);
//   - entries silent for PRUNE_AFTER (default 30 days) are deleted.
//
// PRIVACY TRADE-OFF: profile keys are published so the group creator can add members as
// full members (the server only issues their profile-key credentials to holders of
// their profile key). Anyone who can read this list can decrypt members' profiles and
// derive their sealed-sender access keys. Acceptable for throwaway test accounts with
// fake numbers; not for real users.
//
// No dependencies. State is one JSON file, rewritten atomically.
//
//   node directory.js [port] [dataDir]

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const PORT = Number(process.argv[2] || 8080);
const DATA_DIR = process.argv[3] || '/data';
const FILE = path.join(DATA_DIR, 'directory.json');
const MAX_ENTRIES = 2000;
const HOUR = 60 * 60 * 1000;
const durationEnv = (name, fallback) => {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
};
const ACTIVE_WINDOW = durationEnv('DIRECTORY_ACTIVE_WINDOW_MS', HOUR);
const TAKEOVER_AFTER = durationEnv('DIRECTORY_TAKEOVER_AFTER_MS', 24 * HOUR);
const PRUNE_AFTER = durationEnv('DIRECTORY_PRUNE_AFTER_MS', 30 * 24 * HOUR);
const MAX_BODY = 4096;
// Shared with the browser-member containers only: marks their entries as public.
const PUBLIC_TOKEN = process.env.DIRECTORY_PUBLIC_TOKEN || '';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const PNI = /^PNI:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const E164 = /^\+[1-9][0-9]{6,14}$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

let entries = {};
try {
  entries = JSON.parse(fs.readFileSync(FILE, 'utf8'));
} catch {
  entries = {};
}

function save() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${FILE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(entries));
  fs.renameSync(tmp, FILE);
}

const hash = secret => crypto.createHash('sha256').update(secret).digest('hex');

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

const householdOf = header =>
  typeof header === 'string' && header.length >= 32 && header.length <= 128
    ? hash(`household:${header}`)
    : undefined;

// The entries a caller may see: the public ones, plus its own household's.
function visibleTo(householdHash) {
  const activeSince = Date.now() - ACTIVE_WINDOW;
  return Object.values(entries)
    .filter(entry => entry.updatedAt >= activeSince)
    .filter(entry => entry.public || (householdHash && entry.householdHash === householdHash))
    .map(({ secretHash, householdHash: _household, ...rest }) => rest);
}

const isPublicCaller = header =>
  PUBLIC_TOKEN.length >= 16 &&
  typeof header === 'string' &&
  header.length === PUBLIC_TOKEN.length &&
  crypto.timingSafeEqual(Buffer.from(header), Buffer.from(PUBLIC_TOKEN));

function prune() {
  const cutoff = Date.now() - PRUNE_AFTER;
  let removed = 0;
  for (const [aci, entry] of Object.entries(entries)) {
    if (entry.updatedAt < cutoff) {
      delete entries[aci];
      removed += 1;
    }
  }
  if (removed) {
    save();
    console.log(`directory: pruned ${removed} entries silent for over ${PRUNE_AFTER}ms`);
  }
}

function validate(aci, body) {
  if (!UUID.test(aci)) return 'aci must be a uuid';
  if (!body || typeof body !== 'object') return 'body must be a JSON object';
  if (typeof body.e164 !== 'string' || !E164.test(body.e164)) return 'e164 must be +digits';
  if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 40) {
    return 'name must be 1-40 characters';
  }
  if (body.pni !== undefined && (typeof body.pni !== 'string' || !PNI.test(body.pni))) {
    return 'pni must be PNI:<uuid>';
  }
  if (
    body.profileKey !== undefined &&
    (typeof body.profileKey !== 'string' || body.profileKey.length > 64 || !BASE64.test(body.profileKey))
  ) {
    return 'profileKey must be base64';
  }
  return undefined;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://directory');
  const parts = url.pathname.split('/').filter(Boolean); // ['personas', 'directory', aci?]
  if (parts[0] !== 'personas' || parts[1] !== 'directory' || parts.length > 4) {
    return send(res, 404, { error: 'not found' });
  }

  if (req.method === 'GET' && parts.length === 2) {
    return send(res, 200, visibleTo(householdOf(req.headers['x-personas-household'])));
  }

  // Is this number in use? A new install asks before registering one (registering a
  // taken number would take over that tester's account on the test server).
  if (req.method === 'GET' && parts.length === 4 && parts[2] === 'number') {
    const e164 = decodeURIComponent(parts[3]);
    if (!E164.test(e164)) return send(res, 400, { error: 'e164 must be +digits' });
    const cutoff = Date.now() - TAKEOVER_AFTER;
    const taken = Object.values(entries).some(e => e.e164 === e164 && e.updatedAt >= cutoff);
    return send(res, 200, { taken });
  }

  if (req.method !== 'PUT' || parts.length !== 3) {
    return send(res, 405, { error: 'method not allowed' });
  }

  const aci = parts[2].toLowerCase();
  const secret = req.headers['x-personas-directory-secret'];
  if (typeof secret !== 'string' || secret.length < 32 || secret.length > 128) {
    return send(res, 401, { error: 'missing or malformed x-personas-directory-secret' });
  }

  let raw = '';
  let tooBig = false;
  req.on('data', chunk => {
    raw += chunk;
    if (raw.length > MAX_BODY) {
      tooBig = true;
      req.destroy();
    }
  });
  req.on('end', () => {
    if (tooBig) return send(res, 413, { error: 'body too large' });
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      return send(res, 400, { error: 'body must be JSON' });
    }
    const problem = validate(aci, body);
    if (problem) return send(res, 400, { error: problem });

    const existing = entries[aci];
    const stale = existing && Date.now() - existing.updatedAt > TAKEOVER_AFTER;
    if (existing && existing.secretHash !== hash(secret) && !stale) {
      return send(res, 403, { error: 'this entry belongs to another install' });
    }
    if (!existing && Object.keys(entries).length >= MAX_ENTRIES) {
      return send(res, 507, { error: 'directory full' });
    }
    const takenNumber = Object.values(entries).find(
      e => e.e164 === body.e164 && e.aci !== aci && Date.now() - e.updatedAt <= TAKEOVER_AFTER
    );
    if (takenNumber) {
      if (takenNumber.secretHash !== hash(secret)) {
        return send(res, 409, { error: 'number already listed for another account' });
      }
      // The same install re-registered its number as a new account (the test server
      // forgot the old one when it restarted): move the listing to the new account id.
      delete entries[takenNumber.aci];
      console.log(`directory: moved ${body.e164} from ${takenNumber.aci} to ${aci}`);
    }

    entries[aci] = {
      aci,
      pni: body.pni,
      e164: body.e164,
      name: body.name.trim(),
      profileKey: body.profileKey,
      public: isPublicCaller(req.headers['x-personas-directory-public']),
      householdHash: householdOf(req.headers['x-personas-household']),
      updatedAt: Date.now(),
      secretHash: hash(secret),
    };
    try {
      save();
    } catch (error) {
      return send(res, 500, { error: `could not save: ${error.message}` });
    }
    const verb = !existing ? 'added' : existing.secretHash === hash(secret) ? 'updated' : 'claimed (stale)';
    console.log(`directory: ${verb} ${aci} (${body.name.trim()})`);
    return send(res, 200, { ok: true });
  });
});

prune();
setInterval(prune, HOUR).unref();

server.listen(PORT, () =>
  console.log(
    `directory: listening on :${PORT}, data in ${FILE} ` +
      `(public entries ${PUBLIC_TOKEN.length >= 16 ? 'enabled' : 'DISABLED: no DIRECTORY_PUBLIC_TOKEN'}) ` +
      `(active ${ACTIVE_WINDOW}ms, takeover ${TAKEOVER_AFTER}ms, prune ${PRUNE_AFTER}ms)`
  )
);
