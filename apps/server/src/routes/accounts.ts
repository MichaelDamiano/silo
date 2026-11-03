import type { FastifyInstance } from 'fastify';
import {
  ChallengeRequest,
  LoginRequest,
  SignupRequest,
  loginPayload,
  signupPayload,
  verify,
  type ChallengeResponse,
  type MeResponse,
  type SessionResponse,
} from '@silo/protocol';
import { z } from 'zod';
import type { Config } from '../config.js';
import { withTransaction, type Db } from '../db.js';
import { HttpError, authFailed } from '../errors.js';
import { createSession, requireAuth } from '../auth.js';
import { hashSecret, randomSecret } from '../secrets.js';

const isUniqueViolation = (err: unknown, constraint: string) =>
  typeof err === 'object' && err !== null && (err as { code?: string; constraint?: string }).code === '23505' &&
  (err as { constraint?: string }).constraint === constraint;

export async function accountRoutes(app: FastifyInstance, opts: { db: Db; config: Config }) {
  const { db, config } = opts;
  const authRateLimit = { rateLimit: { max: config.authRateLimitPerMinute, timeWindow: '1 minute' } };

  /** Marks a challenge used and returns its nonce. Each challenge works once, for one key. */
  async function consumeChallenge(challengeId: string, publicKey: string): Promise<string> {
    const { rows } = await db.query<{ nonce: string }>(
      `UPDATE challenges SET used_at = now()
        WHERE id = $1 AND public_key = $2 AND used_at IS NULL AND expires_at > now()
        RETURNING nonce`,
      [challengeId, publicKey],
    );
    if (!rows[0]) throw authFailed();
    return rows[0].nonce;
  }

  app.post('/v1/auth/challenge', { config: authRateLimit }, async (request): Promise<ChallengeResponse> => {
    const { devicePublicKey } = ChallengeRequest.parse(request.body);
    await db.query(`DELETE FROM challenges WHERE expires_at < now() - interval '1 hour'`);
    const nonce = randomSecret();
    const { rows } = await db.query<{ id: string }>(
      'INSERT INTO challenges (public_key, nonce, expires_at) VALUES ($1, $2, $3) RETURNING id',
      [devicePublicKey, nonce, new Date(Date.now() + config.challengeTtlMs)],
    );
    return { challengeId: rows[0]!.id, nonce };
  });

  app.post('/v1/accounts', { config: authRateLimit }, async (request, reply): Promise<SessionResponse> => {
    const body = SignupRequest.parse(request.body);
    const nonce = await consumeChallenge(body.challengeId, body.devicePublicKey);
    if (!verify(body.signature, signupPayload(nonce, body.username), body.devicePublicKey)) throw authFailed();

    const result = await withTransaction(db, async (client) => {
      const invite = await client.query(
        `UPDATE invites SET uses = uses + 1
          WHERE code_hash = $1 AND uses < max_uses AND expires_at > now()
          RETURNING id`,
        [hashSecret(body.inviteCode)],
      );
      if (!invite.rows[0]) throw new HttpError(403, 'invite is invalid, used up or expired');

      let userId: string;
      try {
        const user = await client.query<{ id: string }>('INSERT INTO users (username) VALUES ($1) RETURNING id', [
          body.username,
        ]);
        userId = user.rows[0]!.id;
      } catch (err) {
        if (isUniqueViolation(err, 'users_username_key')) throw new HttpError(409, 'username is taken');
        throw err;
      }

      let deviceId: string;
      try {
        const device = await client.query<{ id: string }>(
          'INSERT INTO devices (user_id, name, public_key) VALUES ($1, $2, $3) RETURNING id',
          [userId, body.deviceName, body.devicePublicKey],
        );
        deviceId = device.rows[0]!.id;
      } catch (err) {
        if (isUniqueViolation(err, 'devices_public_key_key')) throw new HttpError(409, 'device is already registered');
        throw err;
      }

      const session = await createSession(client, deviceId, config.sessionTtlMs);
      return { userId, deviceId, ...session };
    });

    reply.code(201);
    return {
      token: result.token,
      expiresAt: result.expiresAt.toISOString(),
      userId: result.userId,
      deviceId: result.deviceId,
    };
  });

  app.post('/v1/auth/login', { config: authRateLimit }, async (request): Promise<SessionResponse> => {
    const body = LoginRequest.parse(request.body);
    const nonce = await consumeChallenge(body.challengeId, body.devicePublicKey);
    if (!verify(body.signature, loginPayload(nonce), body.devicePublicKey)) throw authFailed();

    const { rows } = await db.query<{ id: string; user_id: string }>(
      'SELECT id, user_id FROM devices WHERE public_key = $1 AND revoked_at IS NULL',
      [body.devicePublicKey],
    );
    const device = rows[0];
    if (!device) throw authFailed();
    const session = await createSession(db, device.id, config.sessionTtlMs);
    return { token: session.token, expiresAt: session.expiresAt.toISOString(), userId: device.user_id, deviceId: device.id };
  });

  app.post('/v1/auth/logout', { preHandler: requireAuth(db) }, async (request, reply) => {
    await db.query('UPDATE sessions SET revoked_at = now() WHERE id = $1', [request.auth!.sessionId]);
    reply.code(204);
  });

  app.get('/v1/me', { preHandler: requireAuth(db) }, async (request): Promise<MeResponse> => {
    const { userId, deviceId } = request.auth!;
    const user = await db.query<{ username: string }>('SELECT username FROM users WHERE id = $1', [userId]);
    const devices = await db.query<{ id: string; name: string; public_key: string; created_at: Date; revoked_at: Date | null }>(
      'SELECT id, name, public_key, created_at, revoked_at FROM devices WHERE user_id = $1 ORDER BY created_at',
      [userId],
    );
    return {
      id: userId,
      username: user.rows[0]!.username,
      devices: devices.rows.map((d) => ({
        id: d.id,
        name: d.name,
        publicKey: d.public_key,
        createdAt: d.created_at.toISOString(),
        revokedAt: d.revoked_at?.toISOString() ?? null,
        current: d.id === deviceId,
      })),
    };
  });

  const DeviceParams = z.object({ id: z.uuid() });

  /** Revokes one of the caller's own devices and ends all of its sessions. */
  app.post('/v1/devices/:id/revoke', { preHandler: requireAuth(db) }, async (request, reply) => {
    const { id } = DeviceParams.parse(request.params);
    await withTransaction(db, async (client) => {
      const res = await client.query(
        'UPDATE devices SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL',
        [id, request.auth!.userId],
      );
      if (res.rowCount === 0) throw new HttpError(404, 'device not found');
      await client.query('UPDATE sessions SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL', [id]);
    });
    reply.code(204);
  });
}
