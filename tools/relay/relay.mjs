#!/usr/bin/env node
// A Silo relay: forwards raw TCP from LISTEN to UPSTREAM without looking inside.
//
// Run it on any machine that people can reach when the main server address is
// blocked, then add its address to the server's PUBLIC_URLS. TLS is passed
// through untouched, so the relay can't read tokens or messages. The server's
// certificate must also cover the relay's hostname, or clients will refuse it.
//
//   LISTEN=0.0.0.0:443 UPSTREAM=silo.example.com:443 node relay.mjs
import net from 'node:net';

const [listenHost, listenPort] = split(process.env.LISTEN ?? '0.0.0.0:8444');
const [upHost, upPort] = split(process.env.UPSTREAM ?? '');
const MAX_CONNECTIONS = Number(process.env.MAX_CONNECTIONS ?? 2000);
const IDLE_MS = 5 * 60_000;

function split(hostPort) {
  const i = hostPort.lastIndexOf(':');
  const port = Number(hostPort.slice(i + 1));
  if (i < 1 || !port) {
    console.error(`expected host:port, got "${hostPort}"`);
    process.exit(1);
  }
  return [hostPort.slice(0, i).replace(/^\[|\]$/g, ''), port];
}

const server = net.createServer((client) => {
  const up = net.connect(upPort, upHost);
  for (const s of [client, up]) {
    s.setTimeout(IDLE_MS, () => s.destroy());
    s.on('error', () => {
      client.destroy();
      up.destroy();
    });
    s.on('close', () => {
      client.destroy();
      up.destroy();
    });
  }
  client.pipe(up).pipe(client);
});
server.maxConnections = MAX_CONNECTIONS;
server.listen(listenPort, listenHost, () => console.log(`relaying ${listenHost}:${listenPort} -> ${upHost}:${upPort}`));
// No logging of connections or addresses, on purpose.
