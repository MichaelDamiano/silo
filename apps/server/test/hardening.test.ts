import { describe, expect, it } from 'vitest';
import { mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { generateDeviceKeyPair, toBase64Url } from '@silo/protocol';
import { LIMITS, perUserLimit } from '../src/limits.js';
import { serverIdentity } from '../src/routes/server-info.js';
import { app, bearer, db, invite, login, newUser, signup } from './helpers/setup.js';

describe('hardening', () => {
  it('sends headers that stop responses being rendered, framed or leaked', async () => {
    const res = await app.inject({ method: 'GET', url: '/healthz' });
    expect(res.headers['content-security-policy']).toBe("default-src 'none'; frame-ancestors 'none'");
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('keeps only the newest sessions on a device', async () => {
    const key = generateDeviceKeyPair();
    const first = (await signup(key, 'mike', await invite())).json().token as string;
    for (let i = 0; i < LIMITS.sessionsPerDevice; i++) expect((await login(key)).statusCode).toBe(200);
    const active = await db.query('SELECT count(*)::int AS n FROM sessions WHERE revoked_at IS NULL');
    expect(active.rows[0].n).toBe(LIMITS.sessionsPerDevice);
    expect((await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(first) })).statusCode).toBe(401);
  });

  it('rate limits by account, so a fresh session gets no fresh allowance', async () => {
    const key = generateDeviceKeyPair();
    const a = (await signup(key, 'mike', await invite())).json().token as string;
    const b = (await login(key)).json().token as string;
    const { rateLimit } = perUserLimit(db)(1, '1 minute');
    const req = (token?: string) => ({ headers: token ? bearer(token) : {}, ip: '203.0.113.9' }) as never;
    const [ka, kb, anon] = await Promise.all([rateLimit.keyGenerator(req(a)), rateLimit.keyGenerator(req(b)), rateLimit.keyGenerator(req())]);
    expect(ka).toBe(kb);
    expect(ka).toMatch(/^user:/);
    expect(anon).toBe('ip:203.0.113.9');
  });

  it('caps how many unused sign-up codes one person can have out', async () => {
    const u = await newUser('mike');
    for (let i = 0; i < LIMITS.activeInvitesPerUser; i++) {
      expect((await app.inject({ method: 'POST', url: '/v1/invites', headers: u.headers, payload: {} })).statusCode).toBe(201);
    }
    expect((await app.inject({ method: 'POST', url: '/v1/invites', headers: u.headers, payload: {} })).statusCode).toBe(429);
  });

  it('caps how many servers one account can be in', async () => {
    const owner = await newUser('owner');
    const u = await newUser('joiner');
    await db.query(
      `WITH s AS (INSERT INTO spaces (name) SELECT 'x' FROM generate_series(1, $2) RETURNING id)
       INSERT INTO space_members (space_id, user_id, role) SELECT id, $1, 'owner' FROM s`,
      [u.userId, LIMITS.spacesPerUser],
    );
    const space = (await app.inject({ method: 'POST', url: '/v1/spaces', headers: owner.headers, payload: { name: 'S' } })).json();
    const code = (await app.inject({ method: 'POST', url: `/v1/spaces/${space.id}/invites`, headers: owner.headers, payload: {} })).json().code;
    const res = await app.inject({ method: 'POST', url: '/v1/space-invites/join', headers: u.headers, payload: { code } });
    expect(res.statusCode).toBe(429);
  });

  it('refuses to fill a device mailbox past its cap, and accepts large messages below it', async () => {
    const alice = await newUser('alice');
    const bob = await newUser('bob');
    await db.query(`UPDATE devices SET signal_identity_key = 'x', signal_device_id = 1`);
    const space = (await app.inject({ method: 'POST', url: '/v1/spaces', headers: alice.headers, payload: { name: 'S' } })).json();
    const code = (await app.inject({ method: 'POST', url: `/v1/spaces/${space.id}/invites`, headers: alice.headers, payload: {} })).json().code;
    await app.inject({ method: 'POST', url: '/v1/space-invites/join', headers: bob.headers, payload: { code } });
    const bobDevice = (await db.query('SELECT d.id FROM devices d WHERE d.user_id = $1', [bob.userId])).rows[0].id;
    // A full-length message is bigger than the default 16 KB request limit.
    const big = Buffer.alloc(18 * 1024, 1).toString('base64');
    const send = () =>
      app.inject({
        method: 'POST',
        url: '/v1/messages',
        headers: alice.headers,
        payload: { recipientUserId: bob.userId, messages: [{ deviceId: bobDevice, type: 2, body: big }] },
      });
    expect((await send()).statusCode).toBe(202);
    await db.query(
      `INSERT INTO envelopes (recipient_device, sender_user, sender_device, message_type, body)
       SELECT $1, $2, (SELECT id FROM devices WHERE user_id = $2), 2, '\\x00' FROM generate_series(1, $3)`,
      [bobDevice, alice.userId, LIMITS.pendingEnvelopesPerDevice],
    );
    expect((await send()).statusCode).toBe(429);
  });

  it('keeps the server identity secret in a file, never in the database, once a file is set', async () => {
    const saved = (await db.query('SELECT public_key, secret_key FROM server_identity')).rows[0];
    try {
      const before = await serverIdentity(db);
      const file = path.join(await mkdtemp(path.join(tmpdir(), 'silo-key-')), 'server.key');
      const moved = await serverIdentity(db, file);
      expect(moved.publicKey).toBe(before.publicKey);
      expect((await stat(file)).mode & 0o777).toBe(0o600);
      expect((await db.query('SELECT secret_key FROM server_identity')).rows[0].secret_key).toBeNull();
      expect((await serverIdentity(db, file)).publicKey).toBe(before.publicKey);
      expect((await readFile(file, 'utf8')).trim()).toBe(toBase64Url(before.secretKey));
      // A different key in the file would change the server's identity, so it refuses to start.
      const wrong = path.join(path.dirname(file), 'wrong.key');
      await writeFile(wrong, toBase64Url(generateDeviceKeyPair().secretKey));
      await expect(serverIdentity(db, wrong)).rejects.toThrow(/different key/);
    } finally {
      await db.query('UPDATE server_identity SET public_key = $1, secret_key = $2', [saved.public_key, saved.secret_key]);
    }
  });
});
