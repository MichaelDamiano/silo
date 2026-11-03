import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import {
  AckRequest,
  AddPreKeysRequest,
  SendMessagesRequest,
  UploadKeysRequest,
  signalIdentityPayload,
  verify,
  type DeviceBundle,
  type Envelope,
} from '@silo/protocol';
import { z } from 'zod';
import { withTransaction, type Db } from '../db.js';
import { HttpError, authFailed } from '../errors.js';
import { requireAuth } from '../auth.js';

const ENVELOPE_TTL_DAYS = 30;
const perSession = (req: { headers: { authorization?: string }; ip: string }) => req.headers.authorization ?? req.ip;
const limit = (max: number, timeWindow: string) => ({ rateLimit: { max, timeWindow, keyGenerator: perSession } });

/** People can message each other only if they share a server, which keeps strangers out of DMs. */
async function canMessage(q: Db | pg.PoolClient, from: string, to: string): Promise<boolean> {
  if (from === to) return true;
  const { rows } = await q.query(
    `SELECT 1 FROM space_members a JOIN space_members b ON a.space_id = b.space_id
      WHERE a.user_id = $1 AND b.user_id = $2 LIMIT 1`,
    [from, to],
  );
  return rows.length > 0;
}

export async function messagingRoutes(app: FastifyInstance, opts: { db: Db }) {
  const { db } = opts;
  app.addHook('preHandler', requireAuth(db));

  /** Publishes this device's Signal keys. The identity key can be set once and never swapped. */
  app.put('/v1/keys', { config: limit(10, '1 minute') }, async (request) => {
    const body = UploadKeysRequest.parse(request.body);
    const { userId, deviceId } = request.auth!;
    return withTransaction(db, async (client) => {
      await client.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [userId]);
      const dev = await client.query<{ public_key: string; signal_device_id: number | null; signal_identity_key: string | null }>(
        'SELECT public_key, signal_device_id, signal_identity_key FROM devices WHERE id = $1',
        [deviceId],
      );
      const device = dev.rows[0]!;
      if (!verify(body.identitySignature, signalIdentityPayload(deviceId, body.identityKey), device.public_key)) throw authFailed();
      if (device.signal_identity_key && device.signal_identity_key !== body.identityKey) {
        throw new HttpError(409, "this device's encryption identity is already set and can't be replaced");
      }
      let signalDeviceId = device.signal_device_id;
      if (!signalDeviceId) {
        // Never reuse a number, even from a revoked device, so others never confuse two devices.
        const next = await client.query<{ n: number }>(
          'SELECT coalesce(max(signal_device_id), 0)::int + 1 AS n FROM devices WHERE user_id = $1',
          [userId],
        );
        signalDeviceId = next.rows[0]!.n;
        if (signalDeviceId > 127) throw new HttpError(409, 'this account has used up its 127 device slots');
      }
      await client.query(
        `UPDATE devices SET signal_device_id = $2, signal_registration_id = $3, signal_identity_key = $4,
                signal_identity_signature = $5, signed_prekey_id = $6, signed_prekey = $7, signed_prekey_signature = $8,
                kyber_prekey_id = $9, kyber_prekey = $10, kyber_prekey_signature = $11
          WHERE id = $1`,
        [
          deviceId,
          signalDeviceId,
          body.registrationId,
          body.identityKey,
          body.identitySignature,
          body.signedPreKey.id,
          body.signedPreKey.publicKey,
          body.signedPreKey.signature,
          body.kyberPreKey.id,
          body.kyberPreKey.publicKey,
          body.kyberPreKey.signature,
        ],
      );
      await insertPreKeys(client, deviceId, body.oneTimePreKeys);
      return { signalDeviceId };
    });
  });

  async function insertPreKeys(client: pg.PoolClient | Db, deviceId: string, keys: { id: number; publicKey: string }[]) {
    if (!keys.length) return;
    await client.query(
      `INSERT INTO one_time_prekeys (device_id, key_id, public_key)
       SELECT $1, k.id, k.pk FROM unnest($2::int[], $3::text[]) AS k(id, pk)
       ON CONFLICT (device_id, key_id) DO UPDATE SET public_key = excluded.public_key`,
      [deviceId, keys.map((k) => k.id), keys.map((k) => k.publicKey)],
    );
  }

  app.post('/v1/keys/prekeys', { config: limit(10, '1 minute') }, async (request, reply) => {
    const { oneTimePreKeys } = AddPreKeysRequest.parse(request.body);
    await insertPreKeys(db, request.auth!.deviceId, oneTimePreKeys);
    reply.code(204);
  });

  app.get('/v1/keys/count', async (request) => {
    const { rows } = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM one_time_prekeys WHERE device_id = $1', [
      request.auth!.deviceId,
    ]);
    return { count: rows[0]!.n };
  });

  /** Lists a user's devices that can receive messages, without handing out any keys. */
  app.get('/v1/users/:userId/devices', async (request) => {
    const { userId: target } = z.object({ userId: z.uuid() }).parse(request.params);
    const me = request.auth!;
    if (!(await canMessage(db, me.userId, target))) throw new HttpError(404, 'user not found');
    const { rows } = await db.query<{ id: string; signal_device_id: number }>(
      `SELECT id, signal_device_id FROM devices
        WHERE user_id = $1 AND revoked_at IS NULL AND signal_identity_key IS NOT NULL AND id <> $2 ORDER BY signal_device_id`,
      [target, me.deviceId],
    );
    return { devices: rows.map((r) => ({ deviceId: r.id, signalDeviceId: r.signal_device_id })) };
  });

  /**
   * Returns a key bundle for each of a user's devices (or just the ones asked for),
   * handing out one one-time pre-key each.
   */
  app.get('/v1/users/:userId/keys', { config: limit(60, '1 minute') }, async (request) => {
    const { userId: target } = z.object({ userId: z.uuid() }).parse(request.params);
    const { devices: only } = z
      .object({ devices: z.string().optional().transform((v) => (v ? v.split(',') : undefined)).pipe(z.array(z.uuid()).max(128).optional()) })
      .parse(request.query);
    const me = request.auth!;
    if (!(await canMessage(db, me.userId, target))) throw new HttpError(404, 'user not found');
    return withTransaction(db, async (client) => {
      const user = await client.query<{ username: string }>('SELECT username FROM users WHERE id = $1', [target]);
      if (!user.rows[0]) throw new HttpError(404, 'user not found');
      const devs = await client.query<{
        id: string;
        public_key: string;
        signal_device_id: number;
        signal_registration_id: number;
        signal_identity_key: string;
        signal_identity_signature: string;
        signed_prekey_id: number;
        signed_prekey: string;
        signed_prekey_signature: string;
        kyber_prekey_id: number;
        kyber_prekey: string;
        kyber_prekey_signature: string;
      }>(
        `SELECT * FROM devices WHERE user_id = $1 AND revoked_at IS NULL AND signal_identity_key IS NOT NULL AND id <> $2
            AND ($3::uuid[] IS NULL OR id = ANY($3::uuid[]))
          ORDER BY signal_device_id`,
        [target, me.deviceId, only ?? null],
      );
      const devices: DeviceBundle[] = [];
      for (const d of devs.rows) {
        const otk = await client.query<{ key_id: number; public_key: string }>(
          `DELETE FROM one_time_prekeys WHERE ctid = (
             SELECT ctid FROM one_time_prekeys WHERE device_id = $1 ORDER BY key_id LIMIT 1 FOR UPDATE SKIP LOCKED
           ) RETURNING key_id, public_key`,
          [d.id],
        );
        devices.push({
          deviceId: d.id,
          signalDeviceId: d.signal_device_id,
          registrationId: d.signal_registration_id,
          devicePublicKey: d.public_key,
          identityKey: d.signal_identity_key,
          identitySignature: d.signal_identity_signature,
          signedPreKey: { id: d.signed_prekey_id, publicKey: d.signed_prekey, signature: d.signed_prekey_signature },
          kyberPreKey: { id: d.kyber_prekey_id, publicKey: d.kyber_prekey, signature: d.kyber_prekey_signature },
          oneTimePreKey: otk.rows[0] ? { id: otk.rows[0].key_id, publicKey: otk.rows[0].public_key } : null,
        });
      }
      return { userId: target, username: user.rows[0].username, devices };
    });
  });

  /**
   * Stores one encrypted copy per device: every device of the recipient, plus the
   * sender's own other devices. If the list doesn't match, nothing is stored and
   * the sender is told which devices to add or drop.
   */
  app.post('/v1/messages', { config: limit(120, '1 minute') }, async (request, reply) => {
    const body = SendMessagesRequest.parse(request.body);
    const me = request.auth!;
    if (body.recipientUserId === me.userId) throw new HttpError(400, 'use your own user only through your other devices');
    if (!(await canMessage(db, me.userId, body.recipientUserId))) throw new HttpError(404, 'user not found');

    const expected = await db.query<{ id: string; user_id: string }>(
      `SELECT id, user_id FROM devices
        WHERE user_id = ANY($1::uuid[]) AND revoked_at IS NULL AND signal_identity_key IS NOT NULL AND id <> $2`,
      [[body.recipientUserId, me.userId], me.deviceId],
    );
    const want = new Set(expected.rows.map((r) => r.id));
    const got = new Set(body.messages.map((m) => m.deviceId));
    const missing = [...want].filter((id) => !got.has(id));
    const extra = [...got].filter((id) => !want.has(id));
    if (missing.length || extra.length || got.size !== body.messages.length) {
      return reply.code(409).send({ error: 'device list is out of date', missing, extra });
    }
    if (!expected.rows.some((r) => r.user_id === body.recipientUserId)) throw new HttpError(409, "that person hasn't set up encryption on any device yet");

    await db.query(
      `INSERT INTO envelopes (recipient_device, sender_user, sender_device, message_type, body)
       SELECT d, $1, $2, t, decode(b, 'base64') FROM unnest($3::uuid[], $4::smallint[], $5::text[]) AS m(d, t, b)`,
      [me.userId, me.deviceId, body.messages.map((m) => m.deviceId), body.messages.map((m) => m.type), body.messages.map((m) => m.body)],
    );
    app.live.notify(got);
    reply.code(202);
    return { delivered: body.messages.length };
  });

  app.get('/v1/messages', async (request): Promise<{ envelopes: Envelope[] }> => {
    const { deviceId } = request.auth!;
    await db.query(`DELETE FROM envelopes WHERE recipient_device = $1 AND created_at < now() - interval '${ENVELOPE_TTL_DAYS} days'`, [
      deviceId,
    ]);
    const { rows } = await db.query<{
      id: string;
      sender_user: string;
      username: string;
      sender_device: string;
      signal_device_id: number;
      message_type: 2 | 3;
      body: Buffer;
      created_at: Date;
    }>(
      `SELECT e.id, e.sender_user, u.username, e.sender_device, d.signal_device_id, e.message_type, e.body, e.created_at
         FROM envelopes e JOIN users u ON u.id = e.sender_user JOIN devices d ON d.id = e.sender_device
        WHERE e.recipient_device = $1 ORDER BY e.created_at, e.id LIMIT 100`,
      [deviceId],
    );
    return {
      envelopes: rows.map((r) => ({
        id: r.id,
        senderUserId: r.sender_user,
        senderUsername: r.username,
        senderDeviceId: r.sender_device,
        senderSignalDeviceId: r.signal_device_id,
        type: r.message_type,
        body: r.body.toString('base64'),
        receivedAt: r.created_at.toISOString(),
      })),
    };
  });

  app.post('/v1/messages/ack', async (request, reply) => {
    const { ids } = AckRequest.parse(request.body);
    await db.query('DELETE FROM envelopes WHERE recipient_device = $1 AND id = ANY($2::uuid[])', [request.auth!.deviceId, ids]);
    reply.code(204);
  });
}
