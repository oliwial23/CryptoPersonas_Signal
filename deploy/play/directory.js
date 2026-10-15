// Personas member directory: how demo clients find each other without CDSI.
//
// libsignal-net's localTestServer mode has no contact discovery, so each client publishes
// {aci, pni, e164, name, profileKey} here after registering and polls the list to seed
// its contacts. It replaces the shared roster folder, which only worked on one machine.
//
//   GET  /personas/directory            -> [entry, ...]
//   PUT  /personas/directory/<aci>      <- {pni?, e164, name, profileKey?}
//        header x-personas-directory-secret: <random per-install secret>
//
// First writer owns an entry: the hash of the secret sent with the first PUT is kept,
// and later PUTs for that aci must present the same secret. That stops one member from
// renaming or redirecting another; it is not authentication of the Signal account.
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
const MAX_BODY = 4096;

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

function publicView() {
  return Object.values(entries).map(({ secretHash, ...rest }) => rest);
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
  if (parts[0] !== 'personas' || parts[1] !== 'directory' || parts.length > 3) {
    return send(res, 404, { error: 'not found' });
  }

  if (req.method === 'GET' && parts.length === 2) {
    return send(res, 200, publicView());
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
    if (existing && existing.secretHash !== hash(secret)) {
      return send(res, 403, { error: 'this entry belongs to another install' });
    }
    if (!existing && Object.keys(entries).length >= MAX_ENTRIES) {
      return send(res, 507, { error: 'directory full' });
    }
    const takenNumber = Object.values(entries).find(e => e.e164 === body.e164 && e.aci !== aci);
    if (takenNumber) {
      return send(res, 409, { error: 'number already listed for another account' });
    }

    entries[aci] = {
      aci,
      pni: body.pni,
      e164: body.e164,
      name: body.name.trim(),
      profileKey: body.profileKey,
      updatedAt: Date.now(),
      secretHash: hash(secret),
    };
    try {
      save();
    } catch (error) {
      return send(res, 500, { error: `could not save: ${error.message}` });
    }
    console.log(`directory: ${existing ? 'updated' : 'added'} ${aci} (${body.name.trim()})`);
    return send(res, 200, { ok: true });
  });
});

server.listen(PORT, () => console.log(`directory: listening on :${PORT}, data in ${FILE}`));
