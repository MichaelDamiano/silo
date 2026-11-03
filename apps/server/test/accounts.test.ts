import { describe, expect, it } from 'vitest';
import { generateDeviceKeyPair, loginPayload, sign, signupPayload } from '@silo/protocol';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { app, bearer, challenge, databaseUrl, db, invite, login, pub, signup } from './helpers/setup.js';

describe('sign-up', () => {
  it('creates an account with a valid invite and returns a working session', async () => {
    const kp = generateDeviceKeyPair();
    const res = await signup(kp, 'mike', await invite());
    expect(res.statusCode).toBe(201);
    const me = await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(res.json().token) });
    expect(me.statusCode).toBe(200);
    expect(me.json()).toMatchObject({ username: 'mike', devices: [{ name: 'Laptop', publicKey: pub(kp), current: true }] });
  });

  it('rejects a missing or used-up invite', async () => {
    const code = await invite(1);
    expect((await signup(generateDeviceKeyPair(), 'first', code)).statusCode).toBe(201);
    expect((await signup(generateDeviceKeyPair(), 'second', code)).statusCode).toBe(403);
    expect((await signup(generateDeviceKeyPair(), 'third', 'A'.repeat(24))).statusCode).toBe(403);
  });

  it('does not use up the invite when the username is taken', async () => {
    const code = await invite(2);
    expect((await signup(generateDeviceKeyPair(), 'mike', code)).statusCode).toBe(201);
    expect((await signup(generateDeviceKeyPair(), 'mike', code)).statusCode).toBe(409);
    expect((await signup(generateDeviceKeyPair(), 'other', code)).statusCode).toBe(201);
  });

  it('rejects a signature from a different key', async () => {
    const kp = generateDeviceKeyPair();
    const attacker = generateDeviceKeyPair();
    const c = await challenge(kp);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/accounts',
      payload: {
        inviteCode: await invite(),
        username: 'mike',
        deviceName: 'Laptop',
        devicePublicKey: pub(kp),
        recoveryPublicKey: pub(generateDeviceKeyPair()),
        challengeId: c.challengeId,
        signature: sign(signupPayload(c.nonce, 'mike', pub(kp)), attacker.secretKey),
      },
    });
    expect(res.statusCode).toBe(401);
  });

  it('rejects invalid usernames', async () => {
    const res = await signup(generateDeviceKeyPair(), 'Bad Name!', await invite());
    expect(res.statusCode).toBe(400);
  });
});

describe('login', () => {
  it('logs in a registered device', async () => {
    const kp = generateDeviceKeyPair();
    await signup(kp, 'mike', await invite());
    const res = await login(kp);
    expect(res.statusCode).toBe(200);
    expect(res.json().token).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it('rejects an unknown device', async () => {
    expect((await login(generateDeviceKeyPair())).statusCode).toBe(401);
  });

  it('does not accept the same challenge twice', async () => {
    const kp = generateDeviceKeyPair();
    await signup(kp, 'mike', await invite());
    const c = await challenge(kp);
    const payload = { devicePublicKey: pub(kp), challengeId: c.challengeId, signature: sign(loginPayload(c.nonce), kp.secretKey) };
    expect((await app.inject({ method: 'POST', url: '/v1/auth/login', payload })).statusCode).toBe(200);
    expect((await app.inject({ method: 'POST', url: '/v1/auth/login', payload })).statusCode).toBe(401);
  });

  it('does not accept a challenge issued for another key', async () => {
    const kp = generateDeviceKeyPair();
    const other = generateDeviceKeyPair();
    await signup(kp, 'mike', await invite());
    const c = await challenge(other);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { devicePublicKey: pub(kp), challengeId: c.challengeId, signature: sign(loginPayload(c.nonce), kp.secretKey) },
    });
    expect(res.statusCode).toBe(401);
  });

  it('does not accept an expired challenge', async () => {
    const kp = generateDeviceKeyPair();
    await signup(kp, 'mike', await invite());
    const c = await challenge(kp);
    await db.query(`UPDATE challenges SET expires_at = now() - interval '1 second' WHERE id = $1`, [c.challengeId]);
    const res = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { devicePublicKey: pub(kp), challengeId: c.challengeId, signature: sign(loginPayload(c.nonce), kp.secretKey) },
    });
    expect(res.statusCode).toBe(401);
  });
});

describe('sessions and devices', () => {
  it('rejects requests without a valid token', async () => {
    expect((await app.inject({ method: 'GET', url: '/v1/me' })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/v1/me', headers: bearer('A'.repeat(43)) })).statusCode).toBe(401);
  });

  it('logout ends the session', async () => {
    const res = await signup(generateDeviceKeyPair(), 'mike', await invite());
    const token = res.json().token;
    expect((await app.inject({ method: 'POST', url: '/v1/auth/logout', headers: bearer(token) })).statusCode).toBe(204);
    expect((await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(token) })).statusCode).toBe(401);
  });

  it('revoking a device ends its sessions and blocks future logins', async () => {
    const kp = generateDeviceKeyPair();
    const res = await signup(kp, 'mike', await invite());
    const { token, deviceId } = res.json();
    const revoke = await app.inject({ method: 'POST', url: `/v1/devices/${deviceId}/revoke`, headers: bearer(token) });
    expect(revoke.statusCode).toBe(204);
    expect((await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(token) })).statusCode).toBe(401);
    expect((await login(kp)).statusCode).toBe(401);
  });

  it("cannot revoke another user's device", async () => {
    const code = await invite(2);
    const a = (await signup(generateDeviceKeyPair(), 'alice', code)).json();
    const b = (await signup(generateDeviceKeyPair(), 'bob', code)).json();
    const res = await app.inject({ method: 'POST', url: `/v1/devices/${b.deviceId}/revoke`, headers: bearer(a.token) });
    expect(res.statusCode).toBe(404);
  });

  it('stores tokens and invite codes only as hashes', async () => {
    const code = await invite();
    const { token } = (await signup(generateDeviceKeyPair(), 'mike', code)).json();
    const dump = await db.query('SELECT row_to_json(s)::text AS j FROM sessions s');
    const invites = await db.query('SELECT row_to_json(i)::text AS j FROM invites i');
    const all = [...dump.rows, ...invites.rows].map((r) => r.j).join();
    expect(all).not.toContain(token);
    expect(all).not.toContain(code);
  });
});

describe('invites', () => {
  it('lets a signed-in user create an invite that works', async () => {
    const { token } = (await signup(generateDeviceKeyPair(), 'mike', await invite())).json();
    const res = await app.inject({ method: 'POST', url: '/v1/invites', headers: bearer(token), payload: { maxUses: 1 } });
    expect(res.statusCode).toBe(201);
    expect((await signup(generateDeviceKeyPair(), 'friend', res.json().code)).statusCode).toBe(201);
  });
});

describe('rate limiting', () => {
  it('limits auth requests per IP', async () => {
    const limited = await buildApp(loadConfig({ DATABASE_URL: databaseUrl, AUTH_RATE_LIMIT_PER_MINUTE: '3' }), db, { logger: false });
    const devicePublicKey = pub(generateDeviceKeyPair());
    const codes: number[] = [];
    for (let i = 0; i < 4; i++) {
      codes.push((await limited.inject({ method: 'POST', url: '/v1/auth/challenge', payload: { devicePublicKey } })).statusCode);
    }
    await limited.close();
    expect(codes).toEqual([200, 200, 200, 429]);
  });
});
