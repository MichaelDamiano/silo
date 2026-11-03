import type { FastifyInstance } from 'fastify';
import { CreateInviteRequest, type CreateInviteResponse } from '@silo/protocol';
import type { Db } from '../db.js';
import { requireAuth } from '../auth.js';
import { createInvite } from '../invites.js';

export async function inviteRoutes(app: FastifyInstance, opts: { db: Db }) {
  const { db } = opts;
  app.post(
    '/v1/invites',
    { preHandler: requireAuth(db), config: { rateLimit: { max: 20, timeWindow: '1 hour' } } },
    async (request, reply): Promise<CreateInviteResponse> => {
      const body = CreateInviteRequest.parse(request.body ?? {});
      const invite = await createInvite(db, { createdBy: request.auth!.userId, ...body });
      reply.code(201);
      return { code: invite.code, maxUses: invite.maxUses, expiresAt: invite.expiresAt.toISOString() };
    },
  );
}
