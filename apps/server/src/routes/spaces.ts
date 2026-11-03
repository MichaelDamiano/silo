import type { FastifyInstance } from 'fastify';
import type pg from 'pg';
import {
  CreateChannelRequest,
  CreateSpaceInviteRequest,
  CreateSpaceRequest,
  JoinSpaceRequest,
  Role,
  SetRoleRequest,
  canManage,
  type SpaceDetail,
  type SpaceInviteResponse,
  type SpaceSummary,
} from '@silo/protocol';
import { z } from 'zod';
import { withTransaction, type Db } from '../db.js';
import { HttpError } from '../errors.js';
import { requireAuth } from '../auth.js';
import { hashSecret, randomSecret } from '../secrets.js';
import { isUniqueViolation } from './accounts.js';

const MAX_OWNED_SPACES = 50;
const MAX_CHANNELS = 100;

const SpaceParams = z.object({ spaceId: z.uuid() });
const ChannelParams = SpaceParams.extend({ channelId: z.uuid() });
const MemberParams = SpaceParams.extend({ userId: z.uuid() });

// Spaces the caller isn't in look the same as spaces that don't exist.
const notFound = () => new HttpError(404, 'server not found');
const forbidden = () => new HttpError(403, "you don't have permission to do that");

type Querier = Db | pg.PoolClient;

/** Signed-in routes are limited per session, so people sharing an IP don't block each other. */
const perSession = (req: { headers: { authorization?: string }; ip: string }) => req.headers.authorization ?? req.ip;
const limit = (max: number, timeWindow: string) => ({ rateLimit: { max, timeWindow, keyGenerator: perSession } });

/** The caller's role in a space, or 404 if they aren't a member. Pass lock to hold the row for the transaction. */
async function roleIn(q: Querier, spaceId: string, userId: string, lock = false): Promise<Role> {
  const { rows } = await q.query<{ role: Role }>(
    `SELECT role FROM space_members WHERE space_id = $1 AND user_id = $2${lock ? ' FOR UPDATE' : ''}`,
    [spaceId, userId],
  );
  if (!rows[0]) throw notFound();
  return rows[0].role;
}

async function requireManager(q: Querier, spaceId: string, userId: string): Promise<Role> {
  const role = await roleIn(q, spaceId, userId);
  if (!canManage(role)) throw forbidden();
  return role;
}

export async function spaceRoutes(app: FastifyInstance, opts: { db: Db }) {
  const { db } = opts;
  app.addHook('preHandler', requireAuth(db));
  const uid = (req: { auth?: { userId: string } }) => req.auth!.userId;

  app.post('/v1/spaces', { config: limit(10, '1 hour') }, async (request, reply): Promise<SpaceSummary> => {
    const { name } = CreateSpaceRequest.parse(request.body);
    const userId = uid(request);
    const id = await withTransaction(db, async (client) => {
      await client.query('SELECT 1 FROM users WHERE id = $1 FOR UPDATE', [userId]);
      const owned = await client.query<{ n: number }>(
        `SELECT count(*)::int AS n FROM space_members WHERE user_id = $1 AND role = 'owner'`,
        [userId],
      );
      if ((owned.rows[0]?.n ?? 0) >= MAX_OWNED_SPACES) throw new HttpError(429, `you can own at most ${MAX_OWNED_SPACES} servers`);
      const space = await client.query<{ id: string }>('INSERT INTO spaces (name) VALUES ($1) RETURNING id', [name]);
      const spaceId = space.rows[0]!.id;
      await client.query(`INSERT INTO space_members (space_id, user_id, role) VALUES ($1, $2, 'owner')`, [spaceId, userId]);
      await client.query(`INSERT INTO channels (space_id, name, position) VALUES ($1, 'general', 0)`, [spaceId]);
      return spaceId;
    });
    reply.code(201);
    return { id, name, role: 'owner' };
  });

  app.get('/v1/spaces', async (request): Promise<{ spaces: SpaceSummary[] }> => {
    const { rows } = await db.query<{ id: string; name: string; role: Role }>(
      `SELECT s.id, s.name, m.role FROM spaces s JOIN space_members m ON m.space_id = s.id
        WHERE m.user_id = $1 ORDER BY m.joined_at`,
      [uid(request)],
    );
    return { spaces: rows };
  });

  app.get('/v1/spaces/:spaceId', async (request): Promise<SpaceDetail> => {
    const { spaceId } = SpaceParams.parse(request.params);
    const role = await roleIn(db, spaceId, uid(request));
    const space = await db.query<{ name: string }>('SELECT name FROM spaces WHERE id = $1', [spaceId]);
    const channels = await db.query<{ id: string; name: string; position: number }>(
      'SELECT id, name, position FROM channels WHERE space_id = $1 ORDER BY position, created_at',
      [spaceId],
    );
    const members = await db.query<{ user_id: string; username: string; role: Role; joined_at: Date }>(
      `SELECT m.user_id, u.username, m.role, m.joined_at FROM space_members m JOIN users u ON u.id = m.user_id
        WHERE m.space_id = $1 ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.username`,
      [spaceId],
    );
    const detail: SpaceDetail = {
      id: spaceId,
      name: space.rows[0]!.name,
      role,
      channels: channels.rows,
      members: members.rows.map((m) => ({ userId: m.user_id, username: m.username, role: m.role, joinedAt: m.joined_at.toISOString() })),
    };
    if (canManage(role)) {
      const bans = await db.query<{ user_id: string; username: string; created_at: Date }>(
        `SELECT b.user_id, u.username, b.created_at FROM space_bans b JOIN users u ON u.id = b.user_id
          WHERE b.space_id = $1 ORDER BY b.created_at DESC`,
        [spaceId],
      );
      detail.bans = bans.rows.map((b) => ({ userId: b.user_id, username: b.username, bannedAt: b.created_at.toISOString() }));
    }
    return detail;
  });

  app.delete('/v1/spaces/:spaceId', async (request, reply) => {
    const { spaceId } = SpaceParams.parse(request.params);
    if ((await roleIn(db, spaceId, uid(request))) !== 'owner') throw forbidden();
    await db.query('DELETE FROM spaces WHERE id = $1', [spaceId]);
    reply.code(204);
  });

  app.post('/v1/spaces/:spaceId/leave', async (request, reply) => {
    const { spaceId } = SpaceParams.parse(request.params);
    const userId = uid(request);
    if ((await roleIn(db, spaceId, userId)) === 'owner') {
      throw new HttpError(409, "the owner can't leave; delete the server instead");
    }
    await db.query('DELETE FROM space_members WHERE space_id = $1 AND user_id = $2', [spaceId, userId]);
    reply.code(204);
  });

  app.post('/v1/spaces/:spaceId/channels', async (request, reply) => {
    const { spaceId } = SpaceParams.parse(request.params);
    const { name } = CreateChannelRequest.parse(request.body);
    const channel = await withTransaction(db, async (client) => {
      await requireManager(client, spaceId, uid(request));
      await client.query('SELECT 1 FROM spaces WHERE id = $1 FOR UPDATE', [spaceId]);
      const count = await client.query<{ n: number; next: number }>(
        'SELECT count(*)::int AS n, coalesce(max(position), -1)::int + 1 AS next FROM channels WHERE space_id = $1',
        [spaceId],
      );
      const { n, next } = count.rows[0]!;
      if (n >= MAX_CHANNELS) throw new HttpError(429, `a server can have at most ${MAX_CHANNELS} channels`);
      try {
        const res = await client.query<{ id: string }>(
          'INSERT INTO channels (space_id, name, position) VALUES ($1, $2, $3) RETURNING id',
          [spaceId, name, next],
        );
        return { id: res.rows[0]!.id, name, position: next };
      } catch (err) {
        if (isUniqueViolation(err, 'channels_space_id_name_key')) throw new HttpError(409, 'a channel with that name already exists');
        throw err;
      }
    });
    reply.code(201);
    return channel;
  });

  app.delete('/v1/spaces/:spaceId/channels/:channelId', async (request, reply) => {
    const { spaceId, channelId } = ChannelParams.parse(request.params);
    await requireManager(db, spaceId, uid(request));
    const res = await db.query('DELETE FROM channels WHERE id = $1 AND space_id = $2', [channelId, spaceId]);
    if (res.rowCount === 0) throw new HttpError(404, 'channel not found');
    reply.code(204);
  });

  app.post('/v1/spaces/:spaceId/invites', async (request, reply): Promise<SpaceInviteResponse> => {
    const { spaceId } = SpaceParams.parse(request.params);
    const body = CreateSpaceInviteRequest.parse(request.body ?? {});
    const userId = uid(request);
    await requireManager(db, spaceId, userId);
    const code = randomSecret(18);
    const expiresAt = new Date(Date.now() + body.expiresInHours * 3600_000);
    await db.query(
      'INSERT INTO space_invites (space_id, code_hash, created_by, max_uses, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [spaceId, hashSecret(code), userId, body.maxUses, expiresAt],
    );
    reply.code(201);
    return { code, maxUses: body.maxUses, expiresAt: expiresAt.toISOString() };
  });

  app.post('/v1/space-invites/join', { config: limit(20, '1 minute') }, async (request): Promise<SpaceSummary> => {
    const { code } = JoinSpaceRequest.parse(request.body);
    const userId = uid(request);
    return withTransaction(db, async (client) => {
      // Check the invite without using it up, so a ban or a repeat join doesn't burn a use.
      const invite = await client.query<{ id: string; space_id: string }>(
        `SELECT id, space_id FROM space_invites
          WHERE code_hash = $1 AND uses < max_uses AND expires_at > now() FOR UPDATE`,
        [hashSecret(code)],
      );
      const found = invite.rows[0];
      if (!found) throw new HttpError(404, 'invite is invalid, used up or expired');
      const banned = await client.query('SELECT 1 FROM space_bans WHERE space_id = $1 AND user_id = $2', [found.space_id, userId]);
      if (banned.rows.length) throw new HttpError(403, "you can't join this server");
      const joined = await client.query(
        `INSERT INTO space_members (space_id, user_id, role) VALUES ($1, $2, 'member') ON CONFLICT DO NOTHING`,
        [found.space_id, userId],
      );
      if (joined.rowCount) await client.query('UPDATE space_invites SET uses = uses + 1 WHERE id = $1', [found.id]);
      const space = await client.query<{ name: string }>('SELECT name FROM spaces WHERE id = $1', [found.space_id]);
      const role = await roleIn(client, found.space_id, userId);
      return { id: found.space_id, name: space.rows[0]!.name, role };
    });
  });

  /** Kick and ban both check that the caller outranks the target. */
  async function removeMember(spaceId: string, actorId: string, targetId: string, ban: boolean) {
    await withTransaction(db, async (client) => {
      const actor = await roleIn(client, spaceId, actorId);
      if (actorId === targetId) throw new HttpError(409, "you can't remove yourself; leave the server instead");
      const target = await client.query<{ role: Role }>(
        'SELECT role FROM space_members WHERE space_id = $1 AND user_id = $2 FOR UPDATE',
        [spaceId, targetId],
      );
      const targetRole = target.rows[0]?.role;
      if (!targetRole && !ban) throw new HttpError(404, 'member not found');
      if (!canManage(actor, targetRole ?? 'member')) throw forbidden();
      if (targetRole) await client.query('DELETE FROM space_members WHERE space_id = $1 AND user_id = $2', [spaceId, targetId]);
      if (ban) {
        const user = await client.query('SELECT 1 FROM users WHERE id = $1', [targetId]);
        if (!user.rows.length) throw new HttpError(404, 'member not found');
        await client.query(
          'INSERT INTO space_bans (space_id, user_id, banned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING',
          [spaceId, targetId, actorId],
        );
      }
    });
  }

  app.post('/v1/spaces/:spaceId/members/:userId/kick', async (request, reply) => {
    const { spaceId, userId } = MemberParams.parse(request.params);
    await removeMember(spaceId, uid(request), userId, false);
    reply.code(204);
  });

  app.post('/v1/spaces/:spaceId/members/:userId/ban', async (request, reply) => {
    const { spaceId, userId } = MemberParams.parse(request.params);
    await removeMember(spaceId, uid(request), userId, true);
    reply.code(204);
  });

  app.delete('/v1/spaces/:spaceId/bans/:userId', async (request, reply) => {
    const { spaceId, userId } = MemberParams.parse(request.params);
    await requireManager(db, spaceId, uid(request));
    const res = await db.query('DELETE FROM space_bans WHERE space_id = $1 AND user_id = $2', [spaceId, userId]);
    if (res.rowCount === 0) throw new HttpError(404, 'ban not found');
    reply.code(204);
  });

  /** Only the owner can promote members to admin or demote admins. */
  app.post('/v1/spaces/:spaceId/members/:userId/role', async (request, reply) => {
    const { spaceId, userId } = MemberParams.parse(request.params);
    const { role } = SetRoleRequest.parse(request.body);
    await withTransaction(db, async (client) => {
      if ((await roleIn(client, spaceId, uid(request))) !== 'owner') throw forbidden();
      const res = await client.query(
        `UPDATE space_members SET role = $3 WHERE space_id = $1 AND user_id = $2 AND role <> 'owner'`,
        [spaceId, userId, role],
      );
      if (res.rowCount === 0) throw new HttpError(404, 'member not found');
    });
    reply.code(204);
  });
}
