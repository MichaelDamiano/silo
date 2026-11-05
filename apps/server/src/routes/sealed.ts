import type { FastifyInstance } from 'fastify';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { ACCESS_KEY_HEADER, AccessKey, SEALED_TYPE, SealedSendRequest, toBase64Url } from '@silo/protocol';
import { issueSenderCertificate, type sealedSenderKeys } from '@silo/signal';
import { z } from 'zod';
import type { Db } from '../db.js';
import { HttpError } from '../errors.js';
import { requireAuth } from '../auth.js';
import { BODY_LIMITS, perUserLimit, requireMailboxRoom } from '../limits.js';

/** Sender certificates last a day; apps fetch a new one well before that. */
export const CERTIFICATE_TTL_MS = 24 * 60 * 60 * 1000;

const noAccess = () => new HttpError(401, 'sealed delivery to this person is not allowed');

/**
 * Sealed sender. A sealed message is dropped in someone's mailbox without saying who
 * sent it, so the server never records who talks to whom. The sender proves who they
 * are to the recipient alone, with a short-lived certificate this server signs and
 * which sits inside the encryption. To keep strangers from flooding mailboxes
 * anonymously, a sealed send needs the recipient's access key, which people only
 * get inside an encrypted message from that recipient.
 */
export async function sealedRoutes(app: FastifyInstance, opts: { db: Db; keys: ReturnType<typeof sealedSenderKeys> }) {
  const { db, keys } = opts;
  const limit = perUserLimit(db);
  const auth = requireAuth(db);

  /** A certificate naming this account, device and Signal identity key, for the recipient to check. */
  app.get('/v1/certificate', { preHandler: auth, config: limit(60, '1 hour') }, async (request) => {
    const { userId, deviceId } = request.auth!;
    const { rows } = await db.query<{ signal_device_id: number | null; signal_identity_key: string | null; username: string }>(
      'SELECT d.signal_device_id, d.signal_identity_key, u.username FROM devices d JOIN users u ON u.id = d.user_id WHERE d.id = $1',
      [deviceId],
    );
    const d = rows[0];
    if (!d?.signal_device_id || !d.signal_identity_key) throw new HttpError(409, 'set up encryption on this device first');
    const expiresAt = Date.now() + CERTIFICATE_TTL_MS;
    const certificate = issueSenderCertificate(keys, {
      userId,
      username: d.username,
      signalDeviceId: d.signal_device_id,
      identityKey: d.signal_identity_key,
      expiresAt,
    });
    return { certificate, expiresAt: new Date(expiresAt).toISOString() };
  });

  /**
   * This account's access key, made on first use. All of an account's devices share
   * it. The server keeps it as is: it only decides who may leave messages here,
   * which the server could do anyway, and it protects nothing else.
   */
  app.get('/v1/access-key', { preHandler: auth }, async (request) => {
    const fresh = toBase64Url(randomBytes(16));
    const { rows } = await db.query<{ access_key: string }>(
      `UPDATE users SET access_key = coalesce(access_key, $2) WHERE id = $1 RETURNING access_key`,
      [request.auth!.userId, fresh],
    );
    return { accessKey: rows[0]!.access_key };
  });

  /** Replaces the access key, for example after blocking someone, so nobody holding the old one can send sealed. */
  app.post('/v1/access-key/rotate', { preHandler: auth, config: limit(30, '1 hour') }, async (request) => {
    const accessKey = toBase64Url(randomBytes(16));
    await db.query('UPDATE users SET access_key = $2 WHERE id = $1', [request.auth!.userId, accessKey]);
    return { accessKey };
  });

  /**
   * Leaves one sealed copy for each of the recipient's devices. No sign-in: the request
   * must not say who is sending. A wrong key and an unknown user get the same answer,
   * so this can't be used to find out which accounts exist.
   */
  app.post(
    '/v1/sealed/:userId/messages',
    { config: { rateLimit: { max: 120, timeWindow: '1 minute' } }, bodyLimit: BODY_LIMITS.directMessage },
    async (request, reply) => {
      if (request.headers.authorization) throw new HttpError(400, "sealed messages are sent without signing in, so they can't be tied to you");
      const { userId } = z.object({ userId: z.uuid() }).parse(request.params);
      const key = AccessKey.safeParse(request.headers[ACCESS_KEY_HEADER]);
      if (!key.success) throw noAccess();
      const user = await db.query<{ access_key: string | null }>('SELECT access_key FROM users WHERE id = $1', [userId]);
      const stored = user.rows[0]?.access_key;
      // Both are 22 characters, which the schema and the generator guarantee.
      if (!stored || !timingSafeEqual(Buffer.from(stored), Buffer.from(key.data))) throw noAccess();

      const body = SealedSendRequest.parse(request.body);
      const devices = await db.query<{ id: string; signal_device_id: number }>(
        `SELECT id, signal_device_id FROM devices
          WHERE user_id = $1 AND revoked_at IS NULL AND signal_identity_key IS NOT NULL ORDER BY signal_device_id`,
        [userId],
      );
      const want = new Set(devices.rows.map((r) => r.id));
      const got = new Set(body.messages.map((m) => m.deviceId));
      if (got.size !== body.messages.length || want.size !== got.size || [...want].some((id) => !got.has(id))) {
        // The sender already holds the access key, so telling them the device list gives nothing away.
        return reply.code(409).send({
          error: 'device list is out of date',
          devices: devices.rows.map((r) => ({ deviceId: r.id, signalDeviceId: r.signal_device_id })),
        });
      }
      await requireMailboxRoom(db, [...want]);
      await db.query(
        `INSERT INTO envelopes (recipient_device, sender_user, sender_device, message_type, body)
         SELECT d, NULL, NULL, $1, decode(b, 'base64') FROM unnest($2::uuid[], $3::text[]) AS m(d, b)`,
        [SEALED_TYPE, body.messages.map((m) => m.deviceId), body.messages.map((m) => m.body)],
      );
      app.live.notify(want);
      reply.code(202);
      return { delivered: body.messages.length };
    },
  );
}
