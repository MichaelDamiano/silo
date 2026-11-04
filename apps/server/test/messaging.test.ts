import { describe, expect, it } from 'vitest';
import WebSocket from 'ws';
import { generateDeviceKeyPair, sign, toBase64Url, type DeviceKeyPair } from '@silo/protocol';
import { MemoryStateStore, SignalDevice } from '@silo/signal';
import { app, bearer, db, invite, login, signup } from './helpers/setup.js';

interface Dev {
  key: DeviceKeyPair;
  token: string;
  userId: string;
  deviceId: string;
  signal: SignalDevice;
  headers: { authorization: string };
}

async function upload(d: Omit<Dev, 'signal'>, store = new MemoryStateStore()): Promise<Dev> {
  const signal = await SignalDevice.open(store);
  const body = await signal.keyUpload(d.deviceId, (p) => sign(p, d.key.secretKey));
  const res = await app.inject({ method: 'PUT', url: '/v1/keys', headers: d.headers, payload: body });
  expect(res.statusCode).toBe(200);
  signal.setAddress(d.userId, res.json().signalDeviceId);
  return { ...d, signal };
}

async function newDevUser(username: string, code?: string): Promise<Dev> {
  const key = generateDeviceKeyPair();
  const res = await signup(key, username, code ?? (await invite()));
  const { token, userId, deviceId } = res.json();
  return upload({ key, token, userId, deviceId, headers: bearer(token) });
}

/** Two users who share a server, each with one device that has published keys. */
async function pair() {
  const alice = await newDevUser('alice');
  const bob = await newDevUser('bob');
  const space = (await app.inject({ method: 'POST', url: '/v1/spaces', headers: alice.headers, payload: { name: 'S' } })).json();
  const code = (await app.inject({ method: 'POST', url: `/v1/spaces/${space.id}/invites`, headers: alice.headers, payload: {} })).json().code;
  await app.inject({ method: 'POST', url: '/v1/space-invites/join', headers: bob.headers, payload: { code } });
  return { alice, bob };
}

const keysOf = (from: Dev, userId: string) => app.inject({ method: 'GET', url: `/v1/users/${userId}/keys`, headers: from.headers });

async function sendDm(from: Dev, to: Dev, text: string) {
  const bundles = (await keysOf(from, to.userId)).json().devices as { deviceId: string; signalDeviceId: number }[];
  const targets = bundles.map((b) => ({ userId: to.userId, deviceId: b.deviceId, signalDeviceId: b.signalDeviceId, bundle: b as never }));
  const messages = await from.signal.encrypt(new TextEncoder().encode(text), targets);
  return app.inject({ method: 'POST', url: '/v1/messages', headers: from.headers, payload: { recipientUserId: to.userId, messages } });
}

async function receive(d: Dev) {
  const { envelopes } = (await app.inject({ method: 'GET', url: '/v1/messages', headers: d.headers })).json();
  const texts: string[] = [];
  for (const e of envelopes) texts.push(new TextDecoder().decode(await d.signal.decrypt(e)));
  if (envelopes.length) {
    await app.inject({ method: 'POST', url: '/v1/messages/ack', headers: d.headers, payload: { ids: envelopes.map((e: { id: string }) => e.id) } });
  }
  return texts;
}

describe('key publishing', () => {
  it('assigns each device its own Signal number, never reused', async () => {
    const key = generateDeviceKeyPair();
    const a = (await signup(key, 'mike', await invite())).json();
    const dev = await upload({ key, token: a.token, userId: a.userId, deviceId: a.deviceId, headers: bearer(a.token) });
    const rows = await db.query('SELECT signal_device_id FROM devices WHERE id = $1', [dev.deviceId]);
    expect(rows.rows[0].signal_device_id).toBe(1);
    // Uploading again keeps the same number.
    const again = await dev.signal.keyUpload(dev.deviceId, (p) => sign(p, key.secretKey));
    expect((await app.inject({ method: 'PUT', url: '/v1/keys', headers: dev.headers, payload: again })).json().signalDeviceId).toBe(1);
  });

  it('rejects an identity not signed by the device, and refuses to swap identities', async () => {
    const key = generateDeviceKeyPair();
    const a = (await signup(key, 'mike', await invite())).json();
    const signal = await SignalDevice.open(new MemoryStateStore());
    const forged = await signal.keyUpload(a.deviceId, (p) => sign(p, generateDeviceKeyPair().secretKey));
    expect((await app.inject({ method: 'PUT', url: '/v1/keys', headers: bearer(a.token), payload: forged })).statusCode).toBe(401);

    await upload({ key, token: a.token, userId: a.userId, deviceId: a.deviceId, headers: bearer(a.token) });
    const other = await (await SignalDevice.open(new MemoryStateStore())).keyUpload(a.deviceId, (p) => sign(p, key.secretKey));
    expect((await app.inject({ method: 'PUT', url: '/v1/keys', headers: bearer(a.token), payload: other })).statusCode).toBe(409);
  });

  it('hands out each one-time pre-key only once', async () => {
    const { alice, bob } = await pair();
    const count = async () => (await app.inject({ method: 'GET', url: '/v1/keys/count', headers: bob.headers })).json().count;
    const before = await count();
    const k1 = (await keysOf(alice, bob.userId)).json().devices[0].oneTimePreKey.id;
    const k2 = (await keysOf(alice, bob.userId)).json().devices[0].oneTimePreKey.id;
    expect(k1).not.toBe(k2);
    expect(await count()).toBe(before - 2);
  });

  it('lists devices without using up keys, and can fetch keys for just some devices', async () => {
    const { alice, bob } = await pair();
    const count = async () => (await app.inject({ method: 'GET', url: '/v1/keys/count', headers: bob.headers })).json().count;
    const before = await count();
    const list = (await app.inject({ method: 'GET', url: `/v1/users/${bob.userId}/devices`, headers: alice.headers })).json();
    expect(list.devices).toEqual([{ deviceId: bob.deviceId, signalDeviceId: 1, publicKey: toBase64Url(bob.key.publicKey) }]);
    expect(await count()).toBe(before);
    const none = await app.inject({ method: 'GET', url: `/v1/users/${bob.userId}/keys?devices=${alice.deviceId}`, headers: alice.headers });
    expect(none.json().devices).toEqual([]);
    expect(await count()).toBe(before);
  });

  it("won't give out keys for someone you don't share a server with", async () => {
    const alice = await newDevUser('alice');
    const eve = await newDevUser('eve');
    expect((await keysOf(eve, alice.userId)).statusCode).toBe(404);
  });
});

describe('direct messages', () => {
  it('delivers an encrypted DM that only the recipient can read', async () => {
    const { alice, bob } = await pair();
    expect((await sendDm(alice, bob, 'hello bob')).statusCode).toBe(202);

    // The server only holds ciphertext.
    const stored = await db.query('SELECT body FROM envelopes');
    expect(stored.rows).toHaveLength(1);
    expect(Buffer.from(stored.rows[0].body).includes(Buffer.from('hello bob'))).toBe(false);

    expect(await receive(bob)).toEqual(['hello bob']);
    expect((await db.query('SELECT 1 FROM envelopes')).rows).toHaveLength(0);

    expect((await sendDm(bob, alice, 'hi alice')).statusCode).toBe(202);
    expect(await receive(alice)).toEqual(['hi alice']);
  });

  it("rejects a send that leaves out one of the recipient's devices", async () => {
    const { alice, bob } = await pair();
    const bundles = (await keysOf(alice, bob.userId)).json().devices;
    // Bob adds a second device after alice fetched his keys.
    const key2 = generateDeviceKeyPair();
    const linkDevice = await db.query<{ id: string }>(
      `INSERT INTO devices (user_id, name, public_key) VALUES ($1, 'Second', $2) RETURNING id`,
      [bob.userId, Buffer.from(key2.publicKey).toString('base64url')],
    );
    const s2 = await login(key2);
    await upload({ key: key2, token: s2.json().token, userId: bob.userId, deviceId: linkDevice.rows[0]!.id, headers: bearer(s2.json().token) });

    const messages = await alice.signal.encrypt(new TextEncoder().encode('x'), bundles.map((b: never) => ({ userId: bob.userId, ...(b as object), bundle: b }) as never));
    const res = await app.inject({ method: 'POST', url: '/v1/messages', headers: alice.headers, payload: { recipientUserId: bob.userId, messages } });
    expect(res.statusCode).toBe(409);
    expect(res.json().missing).toEqual([linkDevice.rows[0]!.id]);

    // With a fresh device list it goes through to both of bob's devices.
    expect((await sendDm(alice, bob, 'both')).statusCode).toBe(202);
    expect((await db.query('SELECT 1 FROM envelopes')).rows).toHaveLength(2);
  });

  it('also sends a copy to the sender’s own other devices', async () => {
    const { alice, bob } = await pair();
    const key2 = generateDeviceKeyPair();
    const d2 = await db.query<{ id: string }>(
      `INSERT INTO devices (user_id, name, public_key) VALUES ($1, 'Desktop', $2) RETURNING id`,
      [alice.userId, Buffer.from(key2.publicKey).toString('base64url')],
    );
    const s2 = (await login(key2)).json();
    await upload({ key: key2, token: s2.token, userId: alice.userId, deviceId: d2.rows[0]!.id, headers: bearer(s2.token) });

    // Without the copy for alice's desktop the server refuses.
    const res = await sendDm(alice, bob, 'x');
    expect(res.statusCode).toBe(409);
    expect(res.json().missing).toEqual([d2.rows[0]!.id]);
  });

  it("won't deliver to someone you don't share a server with", async () => {
    const alice = await newDevUser('alice');
    const eve = await newDevUser('eve');
    const res = await app.inject({
      method: 'POST',
      url: '/v1/messages',
      headers: eve.headers,
      payload: { recipientUserId: alice.userId, messages: [{ deviceId: alice.deviceId, type: 3, body: 'AAAA' }] },
    });
    expect(res.statusCode).toBe(404);
  });

  it("only lets a device fetch and acknowledge its own envelopes", async () => {
    const { alice, bob } = await pair();
    await sendDm(alice, bob, 'secret');
    const ids = (await db.query<{ id: string }>('SELECT id FROM envelopes')).rows.map((r) => r.id);
    expect((await app.inject({ method: 'GET', url: '/v1/messages', headers: alice.headers })).json().envelopes).toEqual([]);
    await app.inject({ method: 'POST', url: '/v1/messages/ack', headers: alice.headers, payload: { ids } });
    expect((await db.query('SELECT 1 FROM envelopes')).rows).toHaveLength(1);
  });
});

describe('live delivery', () => {
  it('nudges a connected device when a message arrives, and drops it when revoked', async () => {
    const { alice, bob } = await pair();
    await app.listen({ port: 0, host: '127.0.0.1' });
    const port = (app.server.address() as { port: number }).port;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/live`);
    const events: string[] = [];
    const closed = new Promise<number>((resolve) => ws.on('close', (code) => resolve(code)));
    await new Promise<void>((resolve) => {
      ws.on('open', () => ws.send(JSON.stringify({ token: bob.token })));
      ws.on('message', (m) => {
        events.push(JSON.parse(m.toString()).type);
        if (events.includes('ready')) resolve();
      });
    });
    await sendDm(alice, bob, 'ping');
    await new Promise((r) => setTimeout(r, 100));
    expect(events.filter((e) => e === 'envelopes').length).toBeGreaterThanOrEqual(2);

    await app.inject({ method: 'POST', url: `/v1/devices/${bob.deviceId}/revoke`, headers: bob.headers });
    expect(await closed).toBe(4001);
  });

  it('closes a connection with a bad token', async () => {
    await app.listen({ port: 0, host: '127.0.0.1' }).catch(() => undefined);
    const port = (app.server.address() as { port: number }).port;
    const ws = new WebSocket(`ws://127.0.0.1:${port}/v1/live`);
    ws.on('open', () => ws.send(JSON.stringify({ token: 'A'.repeat(43) })));
    expect(await new Promise((r) => ws.on('close', (code) => r(code)))).toBe(4001);
  });
});
