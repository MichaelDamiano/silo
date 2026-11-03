import { describe, expect, it } from 'vitest';
import { app, newUser } from './helpers/setup.js';

type User = Awaited<ReturnType<typeof newUser>>;

const req = (user: User, method: 'GET' | 'POST' | 'DELETE', url: string, payload?: object) =>
  app.inject({ method, url, headers: user.headers, ...(payload ? { payload } : {}) });

async function createSpace(owner: User, name = 'Friends') {
  const res = await req(owner, 'POST', '/v1/spaces', { name });
  expect(res.statusCode).toBe(201);
  return res.json().id as string;
}

async function invite(user: User, spaceId: string, maxUses = 10) {
  return req(user, 'POST', `/v1/spaces/${spaceId}/invites`, { maxUses });
}

async function join(user: User, code: string) {
  return req(user, 'POST', '/v1/space-invites/join', { code });
}

/** Creates a space owned by alice, with bob as an admin and carol as a member. */
async function setup() {
  const alice = await newUser('alice');
  const bob = await newUser('bob');
  const carol = await newUser('carol');
  const spaceId = await createSpace(alice);
  const code = (await invite(alice, spaceId)).json().code;
  expect((await join(bob, code)).statusCode).toBe(200);
  expect((await join(carol, code)).statusCode).toBe(200);
  expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${bob.userId}/role`, { role: 'admin' })).statusCode).toBe(204);
  return { alice, bob, carol, spaceId, code };
}

describe('servers', () => {
  it('creates a server with a general channel and lists it', async () => {
    const alice = await newUser('alice');
    const spaceId = await createSpace(alice, 'Book club');
    const list = (await req(alice, 'GET', '/v1/spaces')).json();
    expect(list.spaces).toEqual([{ id: spaceId, name: 'Book club', role: 'owner' }]);
    const detail = (await req(alice, 'GET', `/v1/spaces/${spaceId}`)).json();
    expect(detail.channels.map((c: { name: string }) => c.name)).toEqual(['general']);
    expect(detail.members).toMatchObject([{ username: 'alice', role: 'owner' }]);
    expect(detail.bans).toEqual([]);
  });

  it('hides a server from people who are not in it', async () => {
    const alice = await newUser('alice');
    const eve = await newUser('eve');
    const spaceId = await createSpace(alice);
    expect((await req(eve, 'GET', `/v1/spaces/${spaceId}`)).statusCode).toBe(404);
    expect((await req(eve, 'POST', `/v1/spaces/${spaceId}/channels`, { name: 'x' })).statusCode).toBe(404);
    expect((await req(eve, 'POST', `/v1/spaces/${spaceId}/invites`, {})).statusCode).toBe(404);
  });

  it('requires a session', async () => {
    expect((await app.inject({ method: 'GET', url: '/v1/spaces' })).statusCode).toBe(401);
  });
});

describe('invites and joining', () => {
  it('joins with an invite and counts each new member once', async () => {
    const { carol, spaceId, code } = await setup();
    expect((await join(carol, code)).statusCode).toBe(200);
    const list = (await req(carol, 'GET', '/v1/spaces')).json();
    expect(list.spaces).toMatchObject([{ id: spaceId, role: 'member' }]);
  });

  it('stops accepting an invite once it is used up', async () => {
    const alice = await newUser('alice');
    const spaceId = await createSpace(alice);
    const code = (await invite(alice, spaceId, 1)).json().code;
    expect((await join(await newUser('bob'), code)).statusCode).toBe(200);
    expect((await join(await newUser('carol'), code)).statusCode).toBe(404);
  });

  it('only lets owners and admins create invites', async () => {
    const { bob, carol, spaceId } = await setup();
    expect((await invite(bob, spaceId)).statusCode).toBe(201);
    expect((await invite(carol, spaceId)).statusCode).toBe(403);
  });
});

describe('channels', () => {
  it('lets admins add and remove channels but not members', async () => {
    const { alice, bob, carol, spaceId } = await setup();
    const res = await req(bob, 'POST', `/v1/spaces/${spaceId}/channels`, { name: 'Random' });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ name: 'random', position: 1 });
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/channels`, { name: 'random' })).statusCode).toBe(409);
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/channels`, { name: 'mine' })).statusCode).toBe(403);
    expect((await req(carol, 'DELETE', `/v1/spaces/${spaceId}/channels/${res.json().id}`)).statusCode).toBe(403);
    expect((await req(bob, 'DELETE', `/v1/spaces/${spaceId}/channels/${res.json().id}`)).statusCode).toBe(204);
  });

  it('rejects bad channel names', async () => {
    const { alice, spaceId } = await setup();
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/channels`, { name: 'has spaces' })).statusCode).toBe(400);
  });
});

describe('moderation', () => {
  it('lets an admin kick a member, who can rejoin', async () => {
    const { bob, carol, spaceId, code } = await setup();
    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/members/${carol.userId}/kick`)).statusCode).toBe(204);
    expect((await req(carol, 'GET', `/v1/spaces/${spaceId}`)).statusCode).toBe(404);
    expect((await join(carol, code)).statusCode).toBe(200);
  });

  it('keeps a banned user out until they are unbanned', async () => {
    const { alice, bob, carol, spaceId, code } = await setup();
    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/members/${carol.userId}/ban`)).statusCode).toBe(204);
    expect((await join(carol, code)).statusCode).toBe(403);
    const fresh = (await invite(alice, spaceId)).json().code;
    expect((await join(carol, fresh)).statusCode).toBe(403);
    expect((await req(alice, 'GET', `/v1/spaces/${spaceId}`)).json().bans).toMatchObject([{ username: 'carol' }]);
    expect((await req(alice, 'DELETE', `/v1/spaces/${spaceId}/bans/${carol.userId}`)).statusCode).toBe(204);
    expect((await join(carol, code)).statusCode).toBe(200);
  });

  it('does not let members or admins act on people at or above their level', async () => {
    const { alice, bob, carol, spaceId } = await setup();
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/members/${bob.userId}/kick`)).statusCode).toBe(403);
    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/members/${alice.userId}/ban`)).statusCode).toBe(403);
    const dave = await newUser('dave');
    const code = (await invite(alice, spaceId)).json().code;
    await join(dave, code);
    await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${dave.userId}/role`, { role: 'admin' });
    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/members/${dave.userId}/kick`)).statusCode).toBe(403);
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${dave.userId}/kick`)).statusCode).toBe(204);
  });

  it('only lets the owner change roles, and never the owner role', async () => {
    const { alice, bob, carol, spaceId } = await setup();
    expect((await req(bob, 'POST', `/v1/spaces/${spaceId}/members/${carol.userId}/role`, { role: 'admin' })).statusCode).toBe(403);
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${alice.userId}/role`, { role: 'member' })).statusCode).toBe(404);
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${carol.userId}/role`, { role: 'owner' })).statusCode).toBe(400);
  });

  it('can ban someone before they join', async () => {
    const alice = await newUser('alice');
    const eve = await newUser('eve');
    const spaceId = await createSpace(alice);
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/members/${eve.userId}/ban`)).statusCode).toBe(204);
    const code = (await invite(alice, spaceId)).json().code;
    expect((await join(eve, code)).statusCode).toBe(403);
  });
});

describe('leaving and deleting', () => {
  it('lets members leave but not the owner', async () => {
    const { alice, carol, spaceId } = await setup();
    expect((await req(carol, 'POST', `/v1/spaces/${spaceId}/leave`)).statusCode).toBe(204);
    expect((await req(alice, 'POST', `/v1/spaces/${spaceId}/leave`)).statusCode).toBe(409);
  });

  it('only lets the owner delete the server', async () => {
    const { alice, bob, spaceId } = await setup();
    expect((await req(bob, 'DELETE', `/v1/spaces/${spaceId}`)).statusCode).toBe(403);
    expect((await req(alice, 'DELETE', `/v1/spaces/${spaceId}`)).statusCode).toBe(204);
    expect((await req(bob, 'GET', '/v1/spaces')).json().spaces).toEqual([]);
  });
});
