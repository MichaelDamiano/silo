import { describe, expect, it } from 'vitest';
import { generateDeviceKeyPair, sign, type DeviceKeyPair } from '@silo/protocol';
import { MemoryStateStore, SignalDevice } from '@silo/signal';
import { app, bearer, db, invite, signup } from './helpers/setup.js';

interface Dev {
  key: DeviceKeyPair;
  userId: string;
  deviceId: string;
  signal: SignalDevice;
  headers: { authorization: string };
}

async function newDevUser(username: string): Promise<Dev> {
  const key = generateDeviceKeyPair();
  const { token, userId, deviceId } = (await signup(key, username, await invite())).json();
  const headers = bearer(token);
  const signal = await SignalDevice.open(new MemoryStateStore());
  const res = await app.inject({ method: 'PUT', url: '/v1/keys', headers, payload: await signal.keyUpload(deviceId, (p) => sign(p, key.secretKey)) });
  signal.setAddress(userId, res.json().signalDeviceId);
  return { key, userId, deviceId, signal, headers };
}

const req = (d: Dev, method: 'GET' | 'POST' | 'PUT' | 'DELETE', url: string, payload?: object) =>
  app.inject({ method, url, headers: d.headers, ...(payload ? { payload } : {}) });

/** alice owns a server; bob is an admin, carol and eve are members. */
async function setup() {
  const [alice, bob, carol, eve] = await Promise.all(['alice', 'bob', 'carol', 'eve'].map(newDevUser));
  const space = (await req(alice!, 'POST', '/v1/spaces', { name: 'S' })).json();
  const code = (await req(alice!, 'POST', `/v1/spaces/${space.id}/invites`, {})).json().code;
  for (const u of [bob!, carol!, eve!]) expect((await req(u, 'POST', '/v1/space-invites/join', { code })).statusCode).toBe(200);
  await req(alice!, 'POST', `/v1/spaces/${space.id}/members/${bob!.userId}/role`, { role: 'admin' });
  const channelId = (await req(alice!, 'GET', `/v1/spaces/${space.id}`)).json().channels[0].id as string;
  return { alice: alice!, bob: bob!, carol: carol!, eve: eve!, spaceId: space.id as string, channelId };
}

async function sendDm(from: Dev, to: Dev, text: string) {
  const bundles = (await req(from, 'GET', `/v1/users/${to.userId}/keys`)).json().devices as { deviceId: string; signalDeviceId: number }[];
  const targets = bundles.map((b) => ({ userId: to.userId, deviceId: b.deviceId, signalDeviceId: b.signalDeviceId, bundle: b as never }));
  const messages = await from.signal.encrypt(new TextEncoder().encode(text), targets);
  return req(from, 'POST', '/v1/messages', { recipientUserId: to.userId, messages });
}

const inbox = async (d: Dev) => (await req(d, 'GET', '/v1/messages')).json().envelopes as unknown[];

async function channelMessage(from: Dev, channelId: string) {
  const { rows } = await db.query<{ seq: string }>(
    `INSERT INTO channel_messages (channel_id, sender_user, sender_device, body) VALUES ($1, $2, $3, '\\x00') RETURNING seq`,
    [channelId, from.userId, from.deviceId],
  );
  return Number(rows[0]!.seq);
}

describe('blocking', () => {
  it('drops direct messages from someone you blocked, without telling them', async () => {
    const { alice, eve } = await setup();
    expect((await sendDm(eve, alice, 'hi')).statusCode).toBe(202);
    expect(await inbox(alice)).toHaveLength(1);

    expect((await req(alice, 'PUT', `/v1/blocks/${eve.userId}`)).statusCode).toBe(204);
    // What eve had already queued is gone too.
    expect(await inbox(alice)).toHaveLength(0);
    const blocked = await sendDm(eve, alice, 'are you there?');
    expect(blocked.statusCode).toBe(202);
    expect(blocked.json()).toEqual({ delivered: 1 });
    expect(await inbox(alice)).toHaveLength(0);

    // alice can still write to eve, and eve still gets it.
    expect((await sendDm(alice, eve, 'please stop')).statusCode).toBe(202);
    expect(await inbox(eve)).toHaveLength(1);

    expect((await req(alice, 'GET', '/v1/blocks')).json().blocked).toMatchObject([{ userId: eve.userId, username: 'eve' }]);
    expect((await req(alice, 'DELETE', `/v1/blocks/${eve.userId}`)).statusCode).toBe(204);
    expect((await sendDm(eve, alice, 'sorry')).statusCode).toBe(202);
    expect(await inbox(alice)).toHaveLength(1);
  });

  it("refuses to block yourself or someone who doesn't exist", async () => {
    const { alice } = await setup();
    expect((await req(alice, 'PUT', `/v1/blocks/${alice.userId}`)).statusCode).toBe(400);
    expect((await req(alice, 'PUT', '/v1/blocks/00000000-0000-4000-8000-000000000000')).statusCode).toBe(404);
  });
});

describe('reports', () => {
  it('lets a member report a message, and only moderators see the queue', async () => {
    const { alice, bob, carol, eve, spaceId, channelId } = await setup();
    const seq = await channelMessage(eve, channelId);
    const report = { reportedUserId: eve.userId, channelId, messageSeq: seq, reason: 'scam', note: 'fake giveaway', excerpt: 'send me 1 BTC' };
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/reports`, report)).statusCode).toBe(201);
    // Reporting the same message twice doesn't add a second entry.
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/reports`, report)).statusCode).toBe(200);

    expect((await req(carol, 'GET', `/v1/spaces/${spaceId}/reports`)).statusCode).toBe(403);
    expect((await req(eve, 'GET', `/v1/spaces/${spaceId}/reports`)).statusCode).toBe(403);
    const queue = (await req(bob, 'GET', `/v1/spaces/${spaceId}/reports`)).json().reports;
    expect(queue).toMatchObject([
      { channelName: 'general', messageSeq: seq, reason: 'scam', excerpt: 'send me 1 BTC', reporter: { username: 'carol' }, reported: { username: 'eve', isMember: true } },
    ]);

    // After a ban the report still shows who it was about.
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${eve.userId}/ban`)).statusCode).toBe(204);
    expect((await req(alice, 'GET', `/v1/spaces/${spaceId}/reports`)).json().reports[0].reported.isMember).toBe(false);

    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/reports/${queue[0].id}/resolve`, { status: 'resolved' })).statusCode).toBe(204);
    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/reports/${queue[0].id}/resolve`, { status: 'dismissed' })).statusCode).toBe(404);
    expect((await req(bob, 'GET', `/v1/spaces/${spaceId}/reports`)).json().reports).toEqual([]);
    expect((await req(bob, 'GET', `/v1/spaces/${spaceId}/reports?status=closed`)).json().reports).toMatchObject([{ status: 'resolved' }]);
  });

  it("won't pin a report on someone who didn't write the message", async () => {
    const { carol, eve, alice, spaceId, channelId } = await setup();
    const seq = await channelMessage(alice, channelId);
    const res = await req(carol, 'POST', `/v1/spaces/${spaceId}/reports`, { reportedUserId: eve.userId, channelId, messageSeq: seq, reason: 'spam' });
    expect(res.statusCode).toBe(404);
  });

  it('keeps reports inside the server', async () => {
    const { carol, eve, spaceId } = await setup();
    const outsider = await newDevUser('mallory');
    expect((await req(outsider, 'POST', `/v1/spaces/${spaceId}/reports`, { reportedUserId: eve.userId, reason: 'spam' })).statusCode).toBe(404);
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/reports`, { reportedUserId: outsider.userId, reason: 'spam' })).statusCode).toBe(404);
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/reports`, { reportedUserId: carol.userId, reason: 'spam' })).statusCode).toBe(400);
  });
});
