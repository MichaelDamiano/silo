import type { FastifyInstance } from 'fastify';
import { CreateReportRequest, ResolveReportRequest, canManage, type BlockList, type Report, type Role } from '@silo/protocol';
import { z } from 'zod';
import type { Db } from '../db.js';
import { HttpError } from '../errors.js';
import { requireAuth } from '../auth.js';
import { perUserLimit } from '../limits.js';

export const SAFETY_LIMITS = {
  blocksPerUser: 1000,
  openReportsPerUserPerSpace: 20,
};

const notFound = () => new HttpError(404, 'server not found');

async function roleIn(db: Db, spaceId: string, userId: string): Promise<Role> {
  const { rows } = await db.query<{ role: Role }>('SELECT role FROM space_members WHERE space_id = $1 AND user_id = $2', [spaceId, userId]);
  if (!rows[0]) throw notFound();
  return rows[0].role;
}

/** Blocking people, and reporting them to a server's moderators. */
export async function safetyRoutes(app: FastifyInstance, opts: { db: Db }) {
  const { db } = opts;
  const limit = perUserLimit(db);
  app.addHook('preHandler', requireAuth(db));

  app.get('/v1/blocks', async (request): Promise<BlockList> => {
    const { rows } = await db.query<{ id: string; username: string; created_at: Date }>(
      `SELECT u.id, u.username, b.created_at FROM user_blocks b JOIN users u ON u.id = b.blocked_id
        WHERE b.blocker_id = $1 ORDER BY b.created_at`,
      [request.auth!.userId],
    );
    return { blocked: rows.map((r) => ({ userId: r.id, username: r.username, blockedAt: r.created_at.toISOString() })) };
  });

  /**
   * Blocks someone. Their direct messages to you are dropped from then on, and
   * they aren't told. Their channel messages are hidden by your app, not the server,
   * because a channel message is one ciphertext for everyone.
   */
  app.put('/v1/blocks/:userId', { config: limit(60, '1 minute') }, async (request, reply) => {
    const { userId: target } = z.object({ userId: z.uuid() }).parse(request.params);
    const me = request.auth!.userId;
    if (target === me) throw new HttpError(400, "you can't block yourself");
    const exists = await db.query('SELECT 1 FROM users WHERE id = $1', [target]);
    if (!exists.rows[0]) throw new HttpError(404, 'user not found');
    const count = await db.query<{ n: number }>('SELECT count(*)::int AS n FROM user_blocks WHERE blocker_id = $1', [me]);
    if (count.rows[0]!.n >= SAFETY_LIMITS.blocksPerUser) throw new HttpError(429, `you can block at most ${SAFETY_LIMITS.blocksPerUser} people`);
    await db.query('INSERT INTO user_blocks (blocker_id, blocked_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [me, target]);
    // Anything they already queued for you goes too.
    await db.query(
      `DELETE FROM envelopes e USING devices d
        WHERE e.recipient_device = d.id AND d.user_id = $1 AND e.sender_user = $2`,
      [me, target],
    );
    reply.code(204);
  });

  app.delete('/v1/blocks/:userId', async (request, reply) => {
    const { userId: target } = z.object({ userId: z.uuid() }).parse(request.params);
    await db.query('DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2', [request.auth!.userId, target]);
    reply.code(204);
  });

  /** Any member can report someone in the same server to its owner and admins. */
  app.post('/v1/spaces/:spaceId/reports', { config: limit(20, '1 hour') }, async (request, reply) => {
    const { spaceId } = z.object({ spaceId: z.uuid() }).parse(request.params);
    const body = CreateReportRequest.parse(request.body);
    const me = request.auth!.userId;
    await roleIn(db, spaceId, me);
    if (body.reportedUserId === me) throw new HttpError(400, "you can't report yourself");
    // Someone who was just kicked or banned can still be reported.
    const target = await db.query(
      `SELECT 1 FROM space_members WHERE space_id = $1 AND user_id = $2
       UNION ALL SELECT 1 FROM space_bans WHERE space_id = $1 AND user_id = $2`,
      [spaceId, body.reportedUserId],
    );
    if (!target.rows[0]) throw new HttpError(404, "that person isn't in this server");
    if (body.channelId) {
      const ch = await db.query('SELECT 1 FROM channels WHERE id = $1 AND space_id = $2', [body.channelId, spaceId]);
      if (!ch.rows[0]) throw new HttpError(404, 'channel not found');
      if (body.messageSeq) {
        // The message must exist and be from the person reported, so a report can't point at someone else's words.
        const msg = await db.query('SELECT 1 FROM channel_messages WHERE seq = $1 AND channel_id = $2 AND sender_user = $3', [
          body.messageSeq,
          body.channelId,
          body.reportedUserId,
        ]);
        if (!msg.rows[0]) throw new HttpError(404, 'message not found');
      }
    } else if (body.messageSeq) throw new HttpError(400, 'a message number needs a channel');
    const open = await db.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM reports WHERE space_id = $1 AND reporter_id = $2 AND status = 'open'",
      [spaceId, me],
    );
    if (open.rows[0]!.n >= SAFETY_LIMITS.openReportsPerUserPerSpace) {
      throw new HttpError(429, 'you have too many open reports in this server; wait for moderators to handle them');
    }
    const { rows } = await db.query<{ id: string }>(
      `INSERT INTO reports (space_id, channel_id, message_seq, reporter_id, reported_user_id, reason, note, excerpt)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (reporter_id, channel_id, message_seq) WHERE status = 'open' AND message_seq IS NOT NULL DO NOTHING
       RETURNING id`,
      [spaceId, body.channelId ?? null, body.messageSeq ?? null, me, body.reportedUserId, body.reason, body.note, body.excerpt],
    );
    reply.code(rows[0] ? 201 : 200);
    return { reported: true };
  });

  /** The report queue, for owners and admins only. */
  app.get('/v1/spaces/:spaceId/reports', async (request): Promise<{ reports: Report[] }> => {
    const { spaceId } = z.object({ spaceId: z.uuid() }).parse(request.params);
    const { status } = z.object({ status: z.enum(['open', 'closed']).default('open') }).parse(request.query);
    if (!canManage(await roleIn(db, spaceId, request.auth!.userId))) throw new HttpError(403, "you don't have permission to do that");
    const { rows } = await db.query<{
      id: string;
      channel_id: string | null;
      channel_name: string | null;
      message_seq: string | null;
      reporter_id: string | null;
      reporter_name: string | null;
      reported_user_id: string;
      reported_name: string;
      is_member: boolean;
      reason: Report['reason'];
      note: string;
      excerpt: string;
      status: Report['status'];
      created_at: Date;
      resolved_at: Date | null;
    }>(
      `SELECT r.id, r.channel_id, c.name AS channel_name, r.message_seq, r.reporter_id, ru.username AS reporter_name,
              r.reported_user_id, tu.username AS reported_name,
              EXISTS (SELECT 1 FROM space_members m WHERE m.space_id = r.space_id AND m.user_id = r.reported_user_id) AS is_member,
              r.reason, r.note, r.excerpt, r.status, r.created_at, r.resolved_at
         FROM reports r
         JOIN users tu ON tu.id = r.reported_user_id
         LEFT JOIN users ru ON ru.id = r.reporter_id
         LEFT JOIN channels c ON c.id = r.channel_id
        WHERE r.space_id = $1 AND ${status === 'open' ? "r.status = 'open'" : "r.status <> 'open'"}
        ORDER BY r.created_at ${status === 'open' ? 'ASC' : 'DESC'} LIMIT 200`,
      [spaceId],
    );
    return {
      reports: rows.map((r) => ({
        id: r.id,
        channelId: r.channel_id,
        channelName: r.channel_name,
        messageSeq: r.message_seq === null ? null : Number(r.message_seq),
        reporter: r.reporter_id && r.reporter_name ? { userId: r.reporter_id, username: r.reporter_name } : null,
        reported: { userId: r.reported_user_id, username: r.reported_name, isMember: r.is_member },
        reason: r.reason,
        note: r.note,
        excerpt: r.excerpt,
        status: r.status,
        createdAt: r.created_at.toISOString(),
        resolvedAt: r.resolved_at?.toISOString() ?? null,
      })),
    };
  });

  app.post('/v1/spaces/:spaceId/reports/:reportId/resolve', async (request, reply) => {
    const { spaceId, reportId } = z.object({ spaceId: z.uuid(), reportId: z.uuid() }).parse(request.params);
    const { status } = ResolveReportRequest.parse(request.body);
    const me = request.auth!.userId;
    if (!canManage(await roleIn(db, spaceId, me))) throw new HttpError(403, "you don't have permission to do that");
    const { rowCount } = await db.query(
      `UPDATE reports SET status = $3, resolved_by = $4, resolved_at = now()
        WHERE id = $1 AND space_id = $2 AND status = 'open'`,
      [reportId, spaceId, status, me],
    );
    if (!rowCount) throw new HttpError(404, 'report not found or already handled');
    reply.code(204);
  });
}
