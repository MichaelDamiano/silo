import type { FastifyInstance } from 'fastify';
import { CreateInviteRequest, type CreateInviteResponse } from '@silo/protocol';
import type { Db } from '../db.js';
import { requireAuth } from '../auth.js';
import { createInvite } from '../invites.js';
import { HttpError } from '../errors.js';
import { LIMITS, perUserLimit } from '../limits.js';

export async function inviteRoutes(app: FastifyInstance, opts: { db: Db }) {
  const { db } = opts;
  const limit = perUserLimit(db);
  app.post(
    '/v1/invites',
    { preHandler: requireAuth(db), config: limit(20, '1 hour') },
    async (request, reply): Promise<CreateInviteResponse> => {
      const body = CreateInviteRequest.parse(request.body ?? {});
      const { rows } = await db.query<{ n: number }>(
        'SELECT count(*)::int AS n FROM invites WHERE created_by = $1 AND uses < max_uses AND expires_at > now()',
        [request.auth!.userId],
      );
      if (rows[0]!.n >= LIMITS.activeInvitesPerUser) {
        throw new HttpError(429, `you already have ${LIMITS.activeInvitesPerUser} unused sign-up codes; wait for some to be used or expire`);
      }
      const invite = await createInvite(db, { createdBy: request.auth!.userId, ...body });
      reply.code(201);
      return { code: invite.code, maxUses: invite.maxUses, expiresAt: invite.expiresAt.toISOString() };
    },
  );
}
