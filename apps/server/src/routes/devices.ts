import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'node:crypto';
import {
  ApproveLinkRequest,
  LinkRequest,
  PairingCode,
  PublicKey,
  RecoverRequest,
  RotateRecoveryRequest,
  fingerprint,
  linkApprovePayload,
  linkRequestPayload,
  recoverPayload,
  rotateRecoveryPayload,
  toBase32,
  verify,
  type LinkRequestResponse,
  type PendingLink,
  type SessionResponse,
} from '@silo/protocol';
import { z } from 'zod';
import type { Config } from '../config.js';
import { withTransaction, type Db } from '../db.js';
import { HttpError, authFailed } from '../errors.js';
import { createSession, requireAuth } from '../auth.js';
import { hashSecret } from '../secrets.js';
import { consumeChallengeIn, isUniqueViolation } from './accounts.js';

const LINK_TTL_MS = 10 * 60_000;
const MAX_PENDING_LINKS = 5;

function newPairingCode(): string {
  // 7 random bytes give 56 bits; the first 10 base32 characters keep 50 of them.
  return toBase32(randomBytes(7)).slice(0, 10);
}

export async function deviceRoutes(app: FastifyInstance, opts: { db: Db; config: Config }) {
  const { db, config } = opts;
  const authRateLimit = { rateLimit: { max: config.authRateLimitPerMinute, timeWindow: '1 minute' } };
  const auth = requireAuth(db);

  /**
   * A new device asks to join an account. The answer looks the same whether or
   * not the username exists, so this can't be used to discover accounts.
   */
  app.post('/v1/device-links', { config: authRateLimit }, async (request, reply): Promise<LinkRequestResponse> => {
    const body = LinkRequest.parse(request.body);
    const nonce = await consumeChallengeIn(db, body.challengeId, body.devicePublicKey);
    if (!verify(body.signature, linkRequestPayload(nonce, body.username, body.deviceName), body.devicePublicKey)) {
      throw authFailed();
    }
    const pairingCode = newPairingCode();
    const expiresAt = new Date(Date.now() + LINK_TTL_MS);
    const user = await db.query<{ id: string }>('SELECT id FROM users WHERE username = $1', [body.username]);
    const userId = user.rows[0]?.id;
    if (userId) {
      await withTransaction(db, async (client) => {
        // Lock the user row so concurrent requests can't exceed the pending-link limit.
        await client.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [userId]);
        await client.query('DELETE FROM device_links WHERE user_id = $1 AND (expires_at < now() OR approved_at IS NOT NULL)', [userId]);
        const pending = await client.query<{ n: number }>('SELECT count(*)::int AS n FROM device_links WHERE user_id = $1', [userId]);
        if ((pending.rows[0]?.n ?? 0) >= MAX_PENDING_LINKS) {
          throw new HttpError(429, 'too many devices are waiting for approval; try again later');
        }
        await client.query(
          `INSERT INTO device_links (user_id, pairing_code_hash, device_name, public_key, expires_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [userId, hashSecret(pairingCode), body.deviceName, body.devicePublicKey, expiresAt],
        );
      });
    }
    reply.code(201);
    return { pairingCode, expiresAt: expiresAt.toISOString() };
  });

  /** Lets a waiting device find out when it has been approved, without spending login attempts. */
  app.post('/v1/device-links/status', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (request) => {
    const { devicePublicKey } = z.object({ devicePublicKey: PublicKey }).parse(request.body);
    const { rows } = await db.query('SELECT 1 FROM devices WHERE public_key = $1 AND revoked_at IS NULL', [devicePublicKey]);
    return { approved: rows.length > 0 };
  });

  /** An existing device looks up a pairing code to see which device is asking to join. */
  app.post('/v1/device-links/lookup', { preHandler: auth, config: authRateLimit }, async (request): Promise<PendingLink> => {
    const { pairingCode } = z.object({ pairingCode: PairingCode }).parse(request.body);
    const { rows } = await db.query<{ id: string; device_name: string; public_key: string; expires_at: Date }>(
      `SELECT id, device_name, public_key, expires_at FROM device_links
        WHERE pairing_code_hash = $1 AND user_id = $2 AND approved_at IS NULL AND expires_at > now()`,
      [hashSecret(pairingCode), request.auth!.userId],
    );
    const link = rows[0];
    if (!link) throw new HttpError(404, 'no device is waiting with that code');
    return {
      linkId: link.id,
      deviceName: link.device_name,
      devicePublicKey: link.public_key,
      fingerprint: fingerprint(link.public_key),
      expiresAt: link.expires_at.toISOString(),
    };
  });

  /** An existing device signs the new device's key, which adds it to the account. */
  app.post('/v1/device-links/approve', { preHandler: auth, config: authRateLimit }, async (request, reply) => {
    const body = ApproveLinkRequest.parse(request.body);
    const { userId, deviceId } = request.auth!;
    await withTransaction(db, async (client) => {
      const link = await client.query<{ device_name: string; public_key: string }>(
        `UPDATE device_links SET approved_at = now()
          WHERE id = $1 AND user_id = $2 AND approved_at IS NULL AND expires_at > now()
          RETURNING device_name, public_key`,
        [body.linkId, userId],
      );
      const pending = link.rows[0];
      if (!pending) throw new HttpError(404, 'no device is waiting with that code');
      const approver = await client.query<{ public_key: string }>('SELECT public_key FROM devices WHERE id = $1', [deviceId]);
      if (!verify(body.signature, linkApprovePayload(body.linkId, pending.public_key), approver.rows[0]!.public_key)) {
        throw authFailed();
      }
      try {
        await client.query(
          `INSERT INTO devices (user_id, name, public_key, approved_by, approval_signature)
           VALUES ($1, $2, $3, $4, $5)`,
          [userId, pending.device_name, pending.public_key, deviceId, body.signature],
        );
      } catch (err) {
        if (isUniqueViolation(err, 'devices_public_key_key')) throw new HttpError(409, 'device is already registered');
        throw err;
      }
    });
    reply.code(204);
  });

  /**
   * Regains access with the recovery key after losing every device. All existing
   * devices are revoked, since losing them may mean someone else has them.
   */
  app.post('/v1/accounts/recover', { config: authRateLimit }, async (request, reply): Promise<SessionResponse> => {
    const body = RecoverRequest.parse(request.body);
    const nonce = await consumeChallengeIn(db, body.challengeId, body.devicePublicKey);
    const payload = recoverPayload(nonce, body.username, body.devicePublicKey);
    if (!verify(body.deviceSignature, payload, body.devicePublicKey) || !verify(body.recoverySignature, payload, body.recoveryPublicKey)) {
      throw authFailed();
    }
    const revokedIds: string[] = [];
    const result = await withTransaction(db, async (client) => {
      const user = await client.query<{ id: string }>(
        'SELECT id FROM users WHERE username = $1 AND recovery_public_key = $2 FOR UPDATE',
        [body.username, body.recoveryPublicKey],
      );
      const userId = user.rows[0]?.id;
      if (!userId) throw authFailed();
      await client.query(
        `UPDATE sessions SET revoked_at = now()
          WHERE revoked_at IS NULL AND device_id IN (SELECT id FROM devices WHERE user_id = $1)`,
        [userId],
      );
      const revoked = await client.query<{ id: string }>(
        'UPDATE devices SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL RETURNING id',
        [userId],
      );
      revokedIds.push(...revoked.rows.map((r) => r.id));
      await client.query('DELETE FROM device_links WHERE user_id = $1', [userId]);
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
    app.live.disconnect(revokedIds);
    reply.code(201);
    return { token: result.token, expiresAt: result.expiresAt.toISOString(), userId: result.userId, deviceId: result.deviceId };
  });

  /** Replaces the recovery key, for example after using it or if it may have been seen. */
  app.post('/v1/recovery-key', { preHandler: auth, config: authRateLimit }, async (request, reply) => {
    const body = RotateRecoveryRequest.parse(request.body);
    const { userId } = request.auth!;
    if (!verify(body.signature, rotateRecoveryPayload(userId, body.recoveryPublicKey), body.recoveryPublicKey)) {
      throw authFailed();
    }
    try {
      await db.query('UPDATE users SET recovery_public_key = $1 WHERE id = $2', [body.recoveryPublicKey, userId]);
    } catch (err) {
      if (isUniqueViolation(err, 'users_recovery_public_key_key')) throw new HttpError(409, 'recovery key is already in use');
      throw err;
    }
    reply.code(204);
  });
}
