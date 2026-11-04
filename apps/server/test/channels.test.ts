import { describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { generateDeviceKeyPair, sign, type DeviceKeyPair } from '@silo/protocol';
import { MemoryStateStore, SignalDevice } from '@silo/signal';
import { app, bearer, db, invite, signup } from './helpers/setup.js';

interface Dev {
  key: DeviceKeyPair;
  userId: string;
  deviceId: string;
  signalDeviceId: number;
  signal: SignalDevice;
  headers: { authorization: string };
}

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

async function newDevUser(username: string): Promise<Dev> {
  const key = generateDeviceKeyPair();
  const { token, userId, deviceId } = (await signup(key, username, await invite())).json();
  const headers = bearer(token);
  const signal = await SignalDevice.open(new MemoryStateStore());
  const res = await app.inject({ method: 'PUT', url: '/v1/keys', headers, payload: await signal.keyUpload(deviceId, (p) => sign(p, key.secretKey)) });
  const { signalDeviceId } = res.json();
  signal.setAddress(userId, signalDeviceId);
  return { key, userId, deviceId, signalDeviceId, signal, headers };
}

/** Alice owns a server with #general; the others join it. */
async function group(...names: string[]) {
  const [owner, ...rest] = await Promise.all(['alice', ...names].map(newDevUser));
  const space = (await app.inject({ method: 'POST', url: '/v1/spaces', headers: owner!.headers, payload: { name: 'S' } })).json();
  const detail = (await app.inject({ method: 'GET', url: `/v1/spaces/${space.id}`, headers: owner!.headers })).json();
  const code = (
    await app.inject({ method: 'POST', url: `/v1/spaces/${space.id}/invites`, headers: owner!.headers, payload: { maxUses: 10 } })
  ).json().code;
  for (const d of rest) await app.inject({ method: 'POST', url: '/v1/space-invites/join', headers: d.headers, payload: { code } });
  return { spaceId: space.id as string, channelId: detail.channels[0].id as string, owner: owner!, rest };
}

/** Hands the sender's key for a distribution to the given devices, as the desktop client does. */
async function distribute(from: Dev, spaceId: string, channelId: string, distributionId: string, to: Dev[]) {
  const skdm = await from.signal.senderKeyDistribution(distributionId);
  const payload = enc(JSON.stringify({ v: 1, kind: 'senderKey', spaceId, channelId, distributionId, skdm }));
  const messages = [];
  for (const d of to) {
    const bundles = (await app.inject({ method: 'GET', url: `/v1/users/${d.userId}/keys?devices=${d.deviceId}`, headers: from.headers })).json();
    const target = { userId: d.userId, deviceId: d.deviceId, signalDeviceId: d.signalDeviceId, bundle: bundles.devices[0] };
    messages.push(...(await from.signal.encrypt(payload, [target])));
  }
  return app.inject({ method: 'POST', url: `/v1/spaces/${spaceId}/sender-keys`, headers: from.headers, payload: { messages } });
}

/** Processes any sender keys waiting for this device. */
async function receiveKeys(d: Dev) {
  const { envelopes } = (await app.inject({ method: 'GET', url: '/v1/messages', headers: d.headers })).json();
  for (const e of envelopes) {
    const p = JSON.parse(dec(await d.signal.decrypt(e)));
    if (p.kind === 'senderKey') await d.signal.processSenderKeyDistribution(e.senderUserId, e.senderSignalDeviceId, p.skdm);
  }
}

const post = (d: Dev, channelId: string, body: string) =>
  app.inject({ method: 'POST', url: `/v1/channels/${channelId}/messages`, headers: d.headers, payload: { body } });
const fetchAll = (d: Dev, after = 0) => app.inject({ method: 'GET', url: `/v1/channel-messages?after=${after}`, headers: d.headers });

describe('encrypted channel messages', () => {
  it('stores one ciphertext that every member decrypts with the sender key', async () => {
    const { spaceId, channelId, owner, rest } = await group('bob', 'carol');
    const dist = randomUUID();
    expect((await distribute(owner, spaceId, channelId, dist, rest)).statusCode).toBe(202);
    const body = await owner.signal.groupEncrypt(dist, enc('hello #general'));
    const res = await post(owner, channelId, body);
    expect(res.statusCode).toBe(201);

    for (const d of rest) {
      await receiveKeys(d);
      const { messages } = (await fetchAll(d)).json();
      expect(messages).toHaveLength(1);
      expect(messages[0]).toMatchObject({ channelId, spaceId, senderUserId: owner.userId, senderUsername: 'alice' });
      expect(dec((await d.signal.groupDecrypt(messages[0].senderUserId, messages[0].senderSignalDeviceId, messages[0].body)).plaintext)).toBe(
        'hello #general',
      );
    }
    const stored = await db.query('SELECT body FROM channel_messages');
    expect(stored.rows).toHaveLength(1);
    expect(stored.rows[0].body.toString('latin1')).not.toContain('hello');
    // The sender doesn't get its own message back.
    expect((await fetchAll(owner)).json().messages).toHaveLength(0);
  });

  it('pages with a cursor', async () => {
    const { channelId, owner, rest } = await group('bob');
    for (let i = 0; i < 3; i++) await post(owner, channelId, Buffer.from(`m${i}`).toString('base64'));
    const first = (await fetchAll(rest[0]!)).json().messages;
    expect(first).toHaveLength(3);
    expect((await fetchAll(rest[0]!, first[1].seq)).json().messages).toHaveLength(1);
  });

  it('lists member devices for key handover, and hides servers from non-members', async () => {
    const { spaceId, channelId, owner, rest } = await group('bob');
    const devices = (await app.inject({ method: 'GET', url: `/v1/spaces/${spaceId}/devices`, headers: owner.headers })).json().devices;
    expect(devices).toEqual([{ userId: rest[0]!.userId, deviceId: rest[0]!.deviceId, signalDeviceId: rest[0]!.signalDeviceId }]);

    const eve = await newDevUser('eve');
    expect((await app.inject({ method: 'GET', url: `/v1/spaces/${spaceId}/devices`, headers: eve.headers })).statusCode).toBe(404);
    expect((await post(eve, channelId, 'AAAA')).statusCode).toBe(404);
    await post(owner, channelId, 'AAAA');
    expect((await fetchAll(eve)).json().messages).toHaveLength(0);
  });

  it('refuses to deliver sender keys to devices outside the server', async () => {
    const { spaceId, channelId, owner } = await group('bob');
    const eve = await newDevUser('eve');
    const res = await app.inject({
      method: 'POST',
      url: `/v1/spaces/${spaceId}/sender-keys`,
      headers: owner.headers,
      payload: { messages: [{ deviceId: eve.deviceId, type: 3, body: 'AAAA' }] },
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().extra).toEqual([eve.deviceId]);
    expect(channelId).toBeTruthy();
  });

  it('stops serving a channel to someone who was kicked, and never shows messages from before they joined', async () => {
    const { spaceId, channelId, owner, rest } = await group('bob');
    const bob = rest[0]!;
    await app.inject({ method: 'POST', url: `/v1/spaces/${spaceId}/members/${bob.userId}/kick`, headers: owner.headers, payload: {} });
    await post(owner, channelId, 'AAAA');
    expect((await fetchAll(bob)).json().messages).toHaveLength(0);
    expect((await post(bob, channelId, 'AAAA')).statusCode).toBe(404);

    const dave = await newDevUser('dave');
    const code = (await app.inject({ method: 'POST', url: `/v1/spaces/${spaceId}/invites`, headers: owner.headers, payload: {} })).json().code;
    await app.inject({ method: 'POST', url: '/v1/space-invites/join', headers: dave.headers, payload: { code } });
    expect((await fetchAll(dave)).json().messages).toHaveLength(0);
    await post(owner, channelId, 'BBBB');
    expect((await fetchAll(dave)).json().messages).toHaveLength(1);
  });
});
