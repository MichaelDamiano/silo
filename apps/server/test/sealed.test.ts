import { describe, expect, it } from 'vitest';
import { ACCESS_KEY_HEADER, ServerInfo, generateDeviceKeyPair, sign, type DeviceKeyPair } from '@silo/protocol';
import { MemoryStateStore, SignalDevice } from '@silo/signal';
import { app, bearer, db, invite, login, signup } from './helpers/setup.js';

interface Dev {
  key: DeviceKeyPair;
  userId: string;
  deviceId: string;
  signal: SignalDevice;
  headers: { authorization: string };
}

async function upload(d: Omit<Dev, 'signal'>): Promise<Dev> {
  const signal = await SignalDevice.open(new MemoryStateStore());
  const res = await app.inject({ method: 'PUT', url: '/v1/keys', headers: d.headers, payload: await signal.keyUpload(d.deviceId, (p) => sign(p, d.key.secretKey)) });
  expect(res.statusCode).toBe(200);
  signal.setAddress(d.userId, res.json().signalDeviceId);
  return { ...d, signal };
}

async function newDevUser(username: string): Promise<Dev> {
  const key = generateDeviceKeyPair();
  const { token, userId, deviceId } = (await signup(key, username, await invite())).json();
  return upload({ key, userId, deviceId, headers: bearer(token) });
}

/** A second device on the same account, added straight to the database. */
async function addDevice(owner: Dev): Promise<Dev> {
  const key = generateDeviceKeyPair();
  const { rows } = await db.query<{ id: string }>(`INSERT INTO devices (user_id, name, public_key) VALUES ($1, 'Second', $2) RETURNING id`, [
    owner.userId,
    Buffer.from(key.publicKey).toString('base64url'),
  ]);
  const token = (await login(key)).json().token;
  return upload({ key, userId: owner.userId, deviceId: rows[0]!.id, headers: bearer(token) });
}

async function pair() {
  const alice = await newDevUser('alice');
  const bob = await newDevUser('bob');
  const space = (await app.inject({ method: 'POST', url: '/v1/spaces', headers: alice.headers, payload: { name: 'S' } })).json();
  const code = (await app.inject({ method: 'POST', url: `/v1/spaces/${space.id}/invites`, headers: alice.headers, payload: {} })).json().code;
  await app.inject({ method: 'POST', url: '/v1/space-invites/join', headers: bob.headers, payload: { code } });
  return { alice, bob };
}

async function trustRoot(): Promise<string> {
  const res = await app.inject({ method: 'GET', url: '/v1/server-info?nonce=abcdefghijklmnopqrst' });
  return ServerInfo.parse(JSON.parse(res.json().info)).sealedSenderRoot!;
}

const accessKey = async (d: Dev) => (await app.inject({ method: 'GET', url: '/v1/access-key', headers: d.headers })).json().accessKey as string;
const certificate = async (d: Dev) => (await app.inject({ method: 'GET', url: '/v1/certificate', headers: d.headers })).json().certificate as string;

async function sealedCopies(from: Dev, to: Dev, text: string) {
  const bundles = (await app.inject({ method: 'GET', url: `/v1/users/${to.userId}/keys`, headers: from.headers })).json().devices as {
    deviceId: string;
    signalDeviceId: number;
  }[];
  const targets = bundles.map((b) => ({ userId: to.userId, deviceId: b.deviceId, signalDeviceId: b.signalDeviceId, bundle: b as never }));
  return from.signal.sealedEncrypt(new TextEncoder().encode(text), targets, await certificate(from));
}

const sendSealed = (userId: string, key: string | undefined, messages: unknown[], extra: Record<string, string> = {}) =>
  app.inject({
    method: 'POST',
    url: `/v1/sealed/${userId}/messages`,
    headers: { ...(key ? { [ACCESS_KEY_HEADER]: key } : {}), ...extra },
    payload: { messages },
  });

describe('sealed sender', () => {
  it('delivers a message without the server learning who sent it', async () => {
    const { alice, bob } = await pair();
    const messages = await sealedCopies(alice, bob, 'only bob knows this is from alice');
    expect((await sendSealed(bob.userId, await accessKey(bob), messages)).statusCode).toBe(202);

    // Nothing stored on the server points at alice.
    const stored = await db.query('SELECT sender_user, sender_device, message_type FROM envelopes');
    expect(stored.rows).toEqual([{ sender_user: null, sender_device: null, message_type: 6 }]);

    const { envelopes } = (await app.inject({ method: 'GET', url: '/v1/messages', headers: bob.headers })).json();
    expect(envelopes).toMatchObject([{ type: 6, senderUserId: null, senderUsername: null, senderDeviceId: null, senderSignalDeviceId: null }]);
    const opened = await bob.signal.sealedDecrypt(envelopes[0].body, await trustRoot());
    expect(opened).toMatchObject({ senderUserId: alice.userId, senderUsername: 'alice' });
    expect(new TextDecoder().decode(opened.plaintext)).toBe('only bob knows this is from alice');

    // Bob can now answer over the session the sealed message started.
    const reply = await bob.signal.sealedEncrypt(
      new TextEncoder().encode('hi alice'),
      [{ userId: alice.userId, deviceId: alice.deviceId, signalDeviceId: opened.senderSignalDeviceId }],
      await certificate(bob),
    );
    expect((await sendSealed(alice.userId, await accessKey(alice), reply)).statusCode).toBe(202);
  });

  it("refuses senders without the recipient's access key, and doesn't say whether the account exists", async () => {
    const { alice, bob } = await pair();
    const messages = await sealedCopies(alice, bob, 'x');
    const wrong = await sendSealed(bob.userId, 'AAAAAAAAAAAAAAAAAAAAAA', messages);
    const unknown = await sendSealed('00000000-0000-4000-8000-000000000000', await accessKey(bob), messages);
    const none = await sendSealed(bob.userId, undefined, messages);
    for (const res of [wrong, unknown, none]) {
      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual(wrong.json());
    }
    expect((await db.query('SELECT 1 FROM envelopes')).rows).toHaveLength(0);
  });

  it('refuses a sealed send that is also signed in, so it never gets tied to the sender', async () => {
    const { alice, bob } = await pair();
    const res = await sendSealed(bob.userId, await accessKey(bob), await sealedCopies(alice, bob, 'x'), alice.headers);
    expect(res.statusCode).toBe(400);
  });

  it('stops working with the old key once the recipient rotates it, for example after blocking someone', async () => {
    const { alice, bob } = await pair();
    const old = await accessKey(bob);
    expect(await accessKey(bob)).toBe(old);
    const rotated = (await app.inject({ method: 'POST', url: '/v1/access-key/rotate', headers: bob.headers })).json().accessKey;
    expect(rotated).not.toBe(old);
    expect(await accessKey(bob)).toBe(rotated);
    const messages = await sealedCopies(alice, bob, 'x');
    expect((await sendSealed(bob.userId, old, messages)).statusCode).toBe(401);
    expect((await sendSealed(bob.userId, rotated, messages)).statusCode).toBe(202);
  });

  it("shares one access key across the account's devices and tells the sender about a new device", async () => {
    const { alice, bob } = await pair();
    const key = await accessKey(bob);
    const messages = await sealedCopies(alice, bob, 'x');
    const second = await addDevice(bob);
    expect(await accessKey(second)).toBe(key);

    const res = await sendSealed(bob.userId, key, messages);
    expect(res.statusCode).toBe(409);
    expect(res.json().devices.map((d: { deviceId: string }) => d.deviceId).sort()).toEqual([bob.deviceId, second.deviceId].sort());
    expect((await sendSealed(bob.userId, key, await sealedCopies(alice, bob, 'x'))).statusCode).toBe(202);
    expect((await db.query('SELECT 1 FROM envelopes')).rows).toHaveLength(2);
  });

  it("copies a message to the sender's own other devices with a send to themselves", async () => {
    const { alice } = await pair();
    const other = await addDevice(alice);
    const bundles = (await app.inject({ method: 'GET', url: `/v1/users/${alice.userId}/keys`, headers: alice.headers })).json().devices;
    expect(bundles.map((b: { deviceId: string }) => b.deviceId)).toEqual([other.deviceId]);
    const messages = await alice.signal.encrypt(new TextEncoder().encode('copy'), [
      { userId: alice.userId, deviceId: other.deviceId, signalDeviceId: bundles[0].signalDeviceId, bundle: bundles[0] },
    ]);
    const res = await app.inject({ method: 'POST', url: '/v1/messages', headers: alice.headers, payload: { recipientUserId: alice.userId, messages } });
    expect(res.statusCode).toBe(202);
    const { envelopes } = (await app.inject({ method: 'GET', url: '/v1/messages', headers: other.headers })).json();
    expect(new TextDecoder().decode(await other.signal.decrypt(envelopes[0]))).toBe('copy');
  });

  it('issues sender certificates only to devices that set up encryption', async () => {
    const key = generateDeviceKeyPair();
    const { token } = (await signup(key, 'nokeys', await invite())).json();
    expect((await app.inject({ method: 'GET', url: '/v1/certificate', headers: bearer(token) })).statusCode).toBe(409);
    expect((await app.inject({ method: 'GET', url: '/v1/certificate' })).statusCode).toBe(401);
  });
});
