import { afterEach, describe, expect, it } from 'vitest';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { generateDeviceKeyPair, serverInfoPayload, sign, toBase64Url, type DeviceKeyPair } from '@silo/protocol';
import { ServerDirectory, ServerIdentityError } from './servers.js';
import { DEFAULT_TOR, Transport } from './transport.js';

const closers: (() => void)[] = [];
afterEach(() => {
  while (closers.length) closers.pop()!();
});

/** A stand-in Silo server that answers /v1/server-info signed with its key. */
async function fakeServer(key: DeviceKeyPair, endpoints: () => string[] = () => []) {
  const hits: string[] = [];
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url!, 'http://x');
    hits.push(url.pathname);
    if (url.pathname === '/v1/server-info') {
      const info = JSON.stringify({
        v: 1,
        serverKey: toBase64Url(key.publicKey),
        endpoints: endpoints(),
        issuedAt: new Date().toISOString(),
        nonce: url.searchParams.get('nonce'),
      });
      res.setHeader('content-type', 'application/json');
      return res.end(JSON.stringify({ info, signature: sign(serverInfoPayload(info), key.secretKey) }));
    }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ path: url.pathname }));
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  const close = () => {
    srv.closeAllConnections();
    srv.close();
  };
  closers.push(close);
  return { close, url: `http://localhost:${(srv.address() as AddressInfo).port}`, hits, port: (srv.address() as AddressInfo).port };
}

/** A closed port, so connections are refused like a blocked server. */
async function deadUrl() {
  const s = net.createServer();
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as AddressInfo).port;
  await new Promise((r) => s.close(r));
  return `http://localhost:${port}`;
}

/** A minimal SOCKS5 proxy, standing in for Tor, that maps hostnames to local ports. */
async function fakeTor(routes: Record<string, number>) {
  const seen: string[] = [];
  const srv = net.createServer((c) => {
    c.once('data', () => {
      c.write(Buffer.from([5, 0]));
      c.once('data', (req) => {
        const len = req[4]!;
        const host = req.subarray(5, 5 + len).toString();
        seen.push(host);
        const target = routes[host];
        if (!target) return c.end(Buffer.from([5, 4, 0, 1, 0, 0, 0, 0, 0, 0]));
        const up = net.connect(target, '127.0.0.1', () => {
          c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
          c.pipe(up).pipe(c);
        });
        up.on('error', () => c.destroy());
      });
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
  closers.push(() => srv.close());
  return { port: (srv.address() as AddressInfo).port, seen };
}

const onion = `${'b'.repeat(56)}.onion`;

describe('Transport', () => {
  it('moves to the next address when one is unreachable, and stays there', async () => {
    const key = generateDeviceKeyPair();
    const good = await fakeServer(key);
    const dead = await deadUrl();
    const switched: string[] = [];
    const t = new Transport([dead, good.url], DEFAULT_TOR, (e) => switched.push(e));
    closers.push(() => t.close());
    expect(await (await t.request('/v1/me', {})).json()).toEqual({ path: '/v1/me' });
    expect(t.current).toBe(good.url);
    expect(switched).toEqual([good.url]);
    await t.request('/v1/me', {});
    expect(switched).toHaveLength(1);
  });

  it('retries a send elsewhere only when it never reached a server', async () => {
    const key = generateDeviceKeyPair();
    const good = await fakeServer(key);
    const t = new Transport([await deadUrl(), good.url], DEFAULT_TOR);
    closers.push(() => t.close());
    // Connection refused happens before anything is sent, so a POST may move on.
    const res = await t.request('/v1/messages', { method: 'POST', body: '{}' });
    expect(res.status).toBe(200);
  });

  it('reports every address tried when none work', async () => {
    const t = new Transport([await deadUrl(), await deadUrl()], DEFAULT_TOR);
    closers.push(() => t.close());
    await expect(t.request('/v1/me', {})).rejects.toThrow(/Couldn't reach the server at .*, /);
  });

  it('sends onion addresses through the Tor proxy and lets Tor resolve the name', async () => {
    const key = generateDeviceKeyPair();
    const hidden = await fakeServer(key);
    const tor = await fakeTor({ [onion]: hidden.port });
    const t = new Transport([`http://${onion}`], { ...DEFAULT_TOR, proxyPort: tor.port });
    closers.push(() => t.close());
    expect(t.viaTor()).toBe(true);
    expect(await (await t.request('/v1/me', {})).json()).toEqual({ path: '/v1/me' });
    expect(tor.seen).toEqual([onion]);
  });

  it('can send every connection through Tor', async () => {
    const key = generateDeviceKeyPair();
    const s = await fakeServer(key);
    const tor = await fakeTor({ localhost: s.port });
    const t = new Transport([s.url], { ...DEFAULT_TOR, proxyPort: tor.port, always: true });
    closers.push(() => t.close());
    await t.request('/v1/me', {});
    expect(tor.seen).toEqual(['localhost']);
  });
});

describe('ServerDirectory', () => {
  it('pins the server key and fails over to an address the server published', async () => {
    const key = generateDeviceKeyPair();
    const hidden = await fakeServer(key);
    const tor = await fakeTor({ [onion]: hidden.port });
    const main = await fakeServer(key, () => [`http://${onion}`]);
    const dir = await ServerDirectory.open();
    await dir.setTor({ ...DEFAULT_TOR, proxyPort: tor.port });

    const first = await dir.connect(main.url);
    first.transport.close();
    expect(first.server.endpoints).toEqual([`http://${onion}`]);
    expect(first.server.added).toEqual([main.url]);

    // The main address goes down. The next connection reaches the same server over Tor.
    const mainPort = main.port;
    main.close();
    const again = await dir.connect(`http://localhost:${mainPort}`);
    closers.push(() => again.transport.close());
    expect(again.transport.current).toBe(`http://${onion}`);
    expect(again.server.serverKey).toBe(first.server.serverKey);
  });

  it('refuses an address that answers with a different identity than before', async () => {
    const real = await fakeServer(generateDeviceKeyPair());
    const dir = await ServerDirectory.open();
    (await dir.connect(real.url)).transport.close();
    const port = real.port;
    real.close();
    // Someone else now answers at the same address, with their own key.
    const evil = generateDeviceKeyPair();
    const srv = http.createServer((req, res) => {
      const nonce = new URL(req.url!, 'http://x').searchParams.get('nonce');
      const info = JSON.stringify({ v: 1, serverKey: toBase64Url(evil.publicKey), endpoints: [], issuedAt: new Date().toISOString(), nonce });
      res.end(JSON.stringify({ info, signature: sign(serverInfoPayload(info), evil.secretKey) }));
    });
    await new Promise<void>((r) => srv.listen(port, '127.0.0.1', r));
    closers.push(() => srv.close());
    await expect(dir.connect(real.url)).rejects.toBeInstanceOf(ServerIdentityError);
  });

  it('only adds an address by hand if the same server answers there', async () => {
    const key = generateDeviceKeyPair();
    const main = await fakeServer(key);
    const mirror = await fakeServer(key);
    const other = await fakeServer(generateDeviceKeyPair());
    const dir = await ServerDirectory.open();
    const { server, transport } = await dir.connect(main.url);
    transport.close();
    await expect(dir.addAddress(server.serverKey, other.url)).rejects.toBeInstanceOf(ServerIdentityError);
    const updated = await dir.addAddress(server.serverKey, mirror.url);
    expect(updated.added).toContain(mirror.url);
  });

  it('rejects plain http to anything but localhost and onion addresses', async () => {
    const dir = await ServerDirectory.open();
    await expect(dir.connect('http://chat.example.com')).rejects.toThrow(/https/);
  });
});
