// TLS relay on 127.0.0.1 for one demo member.
//
// libsignal-net only talks to a self-hosted server in its `localTestServer` mode, and that
// mode has no host setting: it always dials `localhost:<chatPort>` and trusts exactly one
// root certificate. Any other serverUrl makes Desktop fall back to the PRODUCTION Signal
// network (ts/textsecure/preconnect.preload.ts). So each member gets this relay: TLS in on
// localhost with a per-container CA, HTTP out to the real backend.
//
// It is an HTTP proxy rather than a byte pipe because the client sends `Host: localhost`,
// and a name-routed front end (the UMIACS load balancer) answers that with its own
// HTTP/1.0 503 -- which libsignal rejects as WrongHttpVersion. Requests and WebSocket
// upgrades are forwarded with Host rewritten to the upstream's name.
//
//   node tls-relay.js <listenPort> <upstreamHost:port> <certDir> [--upstream-tls]
//
// --upstream-tls dials the upstream over TLS (with SNI), for pointing a member at a public
// endpoint such as signalserver.umiacs.umd.edu:443 instead of the in-VM gateway.

'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const tls = require('node:tls');

const [listenPort, upstream, certDir] = process.argv.slice(2);
const upstreamTls = process.argv.includes('--upstream-tls');
if (!listenPort || !upstream || !certDir) {
  console.error('usage: tls-relay.js <listenPort> <upstreamHost:port> <certDir> [--upstream-tls]');
  process.exit(2);
}
const sep = upstream.lastIndexOf(':');
const upHost = upstream.slice(0, sep);
const upPort = Number(upstream.slice(sep + 1));
const upHostHeader = (upstreamTls && upPort === 443) || (!upstreamTls && upPort === 80)
  ? upHost
  : upstream;
const agent = upstreamTls
  ? new https.Agent({ keepAlive: true, servername: upHost, ALPNProtocols: ['http/1.1'] })
  : new http.Agent({ keepAlive: true });

function upstreamHeaders(headers) {
  return { ...headers, host: upHostHeader };
}

const server = https.createServer(
  {
    key: fs.readFileSync(path.join(certDir, 'leaf.key')),
    cert: fs.readFileSync(path.join(certDir, 'leaf.pem')),
    // Desktop pins libsignal to HTTP/1.1 (WebSocket-over-HTTP/2 is unsupported upstream).
    ALPNProtocols: ['http/1.1'],
  },
  (req, res) => {
    const out = (upstreamTls ? https : http).request(
      {
        host: upHost,
        port: upPort,
        method: req.method,
        path: req.url,
        headers: upstreamHeaders(req.headers),
        agent,
      },
      upRes => {
        res.writeHead(upRes.statusCode, upRes.statusMessage, upRes.rawHeaders);
        upRes.pipe(res);
      }
    );
    out.on('error', err => {
      console.error(`tls-relay: ${req.method} ${req.url}: ${err.code || err.message}`);
      if (!res.headersSent) {
        res.writeHead(502);
      }
      res.end();
    });
    req.pipe(out);
  }
);

// WebSocket upgrades: replay the request head with Host rewritten, then splice the sockets.
server.on('upgrade', (req, client, head) => {
  const up = upstreamTls
    ? tls.connect({ host: upHost, port: upPort, servername: upHost, ALPNProtocols: ['http/1.1'] })
    : net.connect({ host: upHost, port: upPort });
  const close = () => {
    client.destroy();
    up.destroy();
  };
  up.on(upstreamTls ? 'secureConnect' : 'connect', () => {
    const lines = [`${req.method} ${req.url} HTTP/1.1`];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      const name = req.rawHeaders[i];
      lines.push(`${name}: ${name.toLowerCase() === 'host' ? upHostHeader : req.rawHeaders[i + 1]}`);
    }
    up.write(`${lines.join('\r\n')}\r\n\r\n`);
    if (head && head.length) {
      up.write(head);
    }
    up.pipe(client).pipe(up);
  });
  up.on('error', err => {
    console.error(`tls-relay: upgrade ${req.url}: ${err.code || err.message}`);
    close();
  });
  client.on('error', close);
});

server.on('tlsClientError', err => {
  // A bare TCP probe (the entrypoint's readiness check) shows up as ECONNRESET; ignore it.
  if (err.code !== 'ECONNRESET') {
    console.error(`tls-relay: client TLS: ${err.code || err.message}`);
  }
});
server.listen(Number(listenPort), '127.0.0.1', () => {
  console.log(
    `tls-relay: https://127.0.0.1:${listenPort} -> ${upstreamTls ? 'https' : 'http'}://${upstream}`
  );
});
