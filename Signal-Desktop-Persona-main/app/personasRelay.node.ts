// Copyright 2026 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// Personas build: the localhost TLS relay, run inside the app.
//
// libsignal-net talks to a self-hosted server only in `localTestServer` mode, which has no
// host setting: it always dials `localhost:<port>` and trusts one private root CA. Any
// other server URL makes Desktop select the PRODUCTION Signal network (refused in personas
// mode; ts/textsecure/preconnect.preload.ts). So the app serves TLS on 127.0.0.1 with a
// per-install CA and forwards each request to the real server.
//
// An HTTP proxy rather than a byte pipe: the client sends `Host: localhost`, and a
// name-routed front end such as the UMIACS load balancer answers that with its own
// HTTP/1.0 503, which libsignal rejects as WrongHttpVersion. Requests and WebSocket
// upgrades are forwarded with Host rewritten to the upstream's name.
//
// Same behaviour as deploy/play/tls-relay.js, which the browser members run beside the app.

import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import type { AddressInfo } from 'node:net';

import { createLogger } from '../ts/logging/log.std.ts';

const log = createLogger('personasRelay');

export type RelayOptions = Readonly<{
  key: string;
  cert: string;
  // host:port of the real server.
  upstream: string;
  // Dial the upstream over TLS (a public endpoint) rather than plain TCP.
  upstreamTls: boolean;
}>;

// Start the relay on an OS-assigned 127.0.0.1 port; resolves to that port.
export function startPersonasRelay(options: RelayOptions): Promise<number> {
  const sep = options.upstream.lastIndexOf(':');
  const upHost = options.upstream.slice(0, sep);
  const upPort = Number(options.upstream.slice(sep + 1));
  const defaultPort = options.upstreamTls ? 443 : 80;
  const upHostHeader = upPort === defaultPort ? upHost : options.upstream;
  const agent = options.upstreamTls
    ? new https.Agent({ keepAlive: true, servername: upHost })
    : new http.Agent({ keepAlive: true });

  const server = https.createServer(
    {
      key: options.key,
      cert: options.cert,
      // Desktop pins libsignal to HTTP/1.1 (WebSocket-over-HTTP/2 is unsupported upstream).
      ALPNProtocols: ['http/1.1'],
    },
    (req, res) => {
      const out = (options.upstreamTls ? https : http).request(
        {
          host: upHost,
          port: upPort,
          method: req.method,
          path: req.url,
          headers: { ...req.headers, host: upHostHeader },
          agent,
        },
        upRes => {
          res.writeHead(upRes.statusCode ?? 502, upRes.statusMessage, upRes.rawHeaders);
          upRes.pipe(res);
        }
      );
      out.on('error', error => {
        log.warn(`${req.method} ${req.url}: ${error.message}`);
        if (!res.headersSent) {
          res.writeHead(502);
        }
        res.end();
      });
      req.pipe(out);
    }
  );

  // WebSocket upgrades: replay the request head with Host rewritten, then splice sockets.
  server.on('upgrade', (req, client, head) => {
    const up = options.upstreamTls
      ? tls.connect({ host: upHost, port: upPort, servername: upHost, ALPNProtocols: ['http/1.1'] })
      : net.connect({ host: upHost, port: upPort });
    const close = () => {
      client.destroy();
      up.destroy();
    };
    up.on(options.upstreamTls ? 'secureConnect' : 'connect', () => {
      const lines = [`${req.method} ${req.url} HTTP/1.1`];
      for (let i = 0; i < req.rawHeaders.length; i += 2) {
        const name = req.rawHeaders[i] ?? '';
        const value =
          name.toLowerCase() === 'host' ? upHostHeader : (req.rawHeaders[i + 1] ?? '');
        lines.push(`${name}: ${value}`);
      }
      up.write(`${lines.join('\r\n')}\r\n\r\n`);
      if (head.length) {
        up.write(head);
      }
      up.pipe(client).pipe(up);
    });
    up.on('error', error => {
      log.warn(`upgrade ${req.url}: ${error.message}`);
      close();
    });
    client.on('error', close);
  });

  server.on('tlsClientError', error => {
    log.warn(`client TLS: ${error.message}`);
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      log.info(
        `relaying https://127.0.0.1:${port} -> ${options.upstreamTls ? 'https' : 'http'}://${options.upstream}`
      );
      resolve(port);
    });
  });
}
