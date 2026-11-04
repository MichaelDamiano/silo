import type { FastifyInstance } from 'fastify';
import { DistributeSenderKeyRequest, PostChannelMessageRequest, type ChannelMessage } from '@silo/protocol';
import { z } from 'zod';
import type { Db } from '../db.js';
import { HttpError } from '../errors.js';
import { requireAuth } from '../auth.js';
import { BODY_LIMITS, perUserLimit, requireMailboxRoom } from '../limits.js';

const CHANNEL_MESSAGE_TTL_DAYS = 30;
const notFound = () => new HttpError(404, 'server not found');

/**
 * Encrypted channel messages using Signal sender keys. Each sender hands its key
 * to every member device over pairwise Signal sessions, then encrypts each channel
 * message once. The server only ever sees ciphertext and who sent it where.
 */
export async function channelRoutes(app: FastifyInstance, opts: { db: Db }) {
  const { db } = opts;
  const limit = perUserLimit(db);
  app.addHook('preHandler', requireAuth(db));

  async function requireMember(spaceId: string, userId: string) {
    const { rows } = await db.query('SELECT 1 FROM space_members WHERE space_id = $1 AND user_id = $2', [spaceId, userId]);
    if (!rows[0]) throw notFound();
  }

  /** Active devices of all current members that can receive encrypted messages. */
  async function memberDevices(spaceId: string, exceptDevice?: string) {
    const { rows } = await db.query<{ user_id: string; username: string; id: string; signal_device_id: number; public_key: string }>(
      `SELECT d.user_id, u.username, d.id, d.signal_device_id, d.public_key
         FROM space_members m JOIN devices d ON d.user_id = m.user_id JOIN users u ON u.id = m.user_id
        WHERE m.space_id = $1 AND d.revoked_at IS NULL AND d.signal_identity_key IS NOT NULL
          AND ($2::uuid IS NULL OR d.id <> $2)
        ORDER BY d.user_id, d.signal_device_id`,
      [spaceId, exceptDevice ?? null],
    );
    return rows;
  }

  app.get('/v1/spaces/:spaceId/devices', async (request) => {
    const { spaceId } = z.object({ spaceId: z.uuid() }).parse(request.params);
    const me = request.auth!;
    await requireMember(spaceId, me.userId);
    const rows = await memberDevices(spaceId, me.deviceId);
    return {
      devices: rows.map((r) => ({
        userId: r.user_id,
        username: r.username,
        deviceId: r.id,
        signalDeviceId: r.signal_device_id,
        publicKey: r.public_key,
      })),
    };
  });

  /** Delivers pairwise copies of the caller's sender key to member devices. Unlike DMs, any subset is allowed. */
  app.post('/v1/spaces/:spaceId/sender-keys', { config: limit(60, '1 minute'), bodyLimit: BODY_LIMITS.senderKeys }, async (request, reply) => {
    const { spaceId } = z.object({ spaceId: z.uuid() }).parse(request.params);
    const { messages } = DistributeSenderKeyRequest.parse(request.body);
    const me = request.auth!;
    await requireMember(spaceId, me.userId);
    const allowed = new Set((await memberDevices(spaceId, me.deviceId)).map((r) => r.id));
    const extra = messages.map((m) => m.deviceId).filter((id) => !allowed.has(id));
    if (extra.length || new Set(messages.map((m) => m.deviceId)).size !== messages.length) {
      return reply.code(409).send({ error: 'device list is out of date', missing: [], extra });
    }
    await requireMailboxRoom(db, messages.map((m) => m.deviceId));
    await db.query(
      `INSERT INTO envelopes (recipient_device, sender_user, sender_device, message_type, body)
       SELECT d, $1, $2, t, decode(b, 'base64') FROM unnest($3::uuid[], $4::smallint[], $5::text[]) AS m(d, t, b)`,
      [me.userId, me.deviceId, messages.map((m) => m.deviceId), messages.map((m) => m.type), messages.map((m) => m.body)],
    );
    app.live.notify(messages.map((m) => m.deviceId));
    reply.code(202);
    return { delivered: messages.length };
  });

  app.post('/v1/channels/:channelId/messages', { config: limit(120, '1 minute'), bodyLimit: BODY_LIMITS.channelMessage }, async (request, reply) => {
    const { channelId } = z.object({ channelId: z.uuid() }).parse(request.params);
    const { body } = PostChannelMessageRequest.parse(request.body);
    const me = request.auth!;
    const ch = await db.query<{ space_id: string }>(
      `SELECT c.space_id FROM channels c JOIN space_members m ON m.space_id = c.space_id AND m.user_id = $2 WHERE c.id = $1`,
      [channelId, me.userId],
    );
    if (!ch.rows[0]) throw new HttpError(404, 'channel not found');
    const { rows } = await db.query<{ seq: string }>(
      `INSERT INTO channel_messages (channel_id, sender_user, sender_device, body) VALUES ($1, $2, $3, decode($4, 'base64')) RETURNING seq`,
      [channelId, me.userId, me.deviceId, body],
    );
    app.live.notify(
      (await memberDevices(ch.rows[0].space_id, me.deviceId)).map((r) => r.id),
      'channel',
    );
    reply.code(201);
    return { seq: Number(rows[0]!.seq) };
  });

  /**
   * Channel messages from every server the caller is in, after a cursor. A device
   * only sees messages sent after both it and its account joined, since it could
   * never decrypt older ones anyway.
   */
  app.get('/v1/channel-messages', async (request): Promise<{ messages: ChannelMessage[] }> => {
    const { after } = z.object({ after: z.coerce.number().int().min(0).default(0) }).parse(request.query);
    const me = request.auth!;
    await db.query(`DELETE FROM channel_messages WHERE created_at < now() - interval '${CHANNEL_MESSAGE_TTL_DAYS} days'`);
    const { rows } = await db.query<{
      seq: string;
      space_id: string;
      channel_id: string;
      sender_user: string;
      username: string;
      sender_device: string;
      signal_device_id: number;
      body: Buffer;
      created_at: Date;
    }>(
      `SELECT cm.seq, c.space_id, cm.channel_id, cm.sender_user, u.username, cm.sender_device, sd.signal_device_id, cm.body, cm.created_at
         FROM channel_messages cm
         JOIN channels c ON c.id = cm.channel_id
         JOIN space_members m ON m.space_id = c.space_id AND m.user_id = $1
         JOIN devices me ON me.id = $2
         JOIN users u ON u.id = cm.sender_user
         JOIN devices sd ON sd.id = cm.sender_device
        WHERE cm.seq > $3 AND cm.sender_device <> $2
          AND cm.created_at >= greatest(m.joined_at, me.created_at)
        ORDER BY cm.seq LIMIT 200`,
      [me.userId, me.deviceId, after],
    );
    return {
      messages: rows.map((r) => ({
        seq: Number(r.seq),
        spaceId: r.space_id,
        channelId: r.channel_id,
        senderUserId: r.sender_user,
        senderUsername: r.username,
        senderDeviceId: r.sender_device,
        senderSignalDeviceId: r.signal_device_id,
        body: r.body.toString('base64'),
        receivedAt: r.created_at.toISOString(),
      })),
    };
  });
}
