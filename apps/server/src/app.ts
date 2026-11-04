import Fastify, { type FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { ZodError } from 'zod';
import type { Config } from './config.js';
import type { Db } from './db.js';
import { HttpError } from './errors.js';
import { accountRoutes } from './routes/accounts.js';
import { deviceRoutes } from './routes/devices.js';
import { inviteRoutes } from './routes/invites.js';
import { spaceRoutes } from './routes/spaces.js';
import { messagingRoutes } from './routes/messaging.js';
import { channelRoutes } from './routes/channels.js';
import { serverInfoRoutes } from './routes/server-info.js';
import { LiveHub, liveRoutes } from './live.js';

export async function buildApp(config: Config, db: Db, opts: { logger?: boolean } = {}): Promise<FastifyInstance> {
  const app = Fastify({
    trustProxy: config.trustProxy,
    bodyLimit: 16 * 1024,
    logger: opts.logger === false
      ? false
      : {
          // Never log IP addresses, headers or bodies: they can identify users or carry tokens.
          serializers: {
            req: (req) => ({ method: req.method, url: req.routeOptions?.url ?? 'unknown' }),
            res: (res) => ({ statusCode: res.statusCode }),
          },
        },
  });

  // Counters live in memory only and are keyed by IP just long enough to rate limit.
  await app.register(rateLimit, { global: true, max: 120, timeWindow: '1 minute' });

  app.addHook('onSend', async (request, reply) => {
    reply.header('cache-control', 'no-store');
    reply.header('x-content-type-options', 'nosniff');
    // This is a JSON API: nothing it returns should ever be rendered, framed or sent onward as a referrer.
    reply.header('content-security-policy', "default-src 'none'; frame-ancestors 'none'");
    reply.header('x-frame-options', 'DENY');
    reply.header('referrer-policy', 'no-referrer');
    reply.header('cross-origin-resource-policy', 'same-origin');
    reply.header('permissions-policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
    if (request.protocol === 'https') reply.header('strict-transport-security', 'max-age=63072000; includeSubDomains');
  });

  app.setErrorHandler((err, request, reply) => {
    if (err instanceof ZodError) {
      return reply.code(400).send({ error: 'invalid request', issues: err.issues.map((i) => ({ path: i.path, message: i.message })) });
    }
    if (err instanceof HttpError) return reply.code(err.statusCode).send({ error: err.message });
    const status = (err as { statusCode?: number }).statusCode;
    if (status && status < 500) return reply.code(status).send({ error: (err as Error).message });
    request.log.error(err);
    return reply.code(500).send({ error: 'internal error' });
  });

  app.decorate('live', new LiveHub());
  app.addHook('onClose', async () => app.live.closeAll());

  app.get('/healthz', async () => ({ ok: true }));
  await app.register(accountRoutes, { db, config });
  await app.register(deviceRoutes, { db, config });
  await app.register(inviteRoutes, { db });
  await app.register(spaceRoutes, { db });
  await app.register(messagingRoutes, { db });
  await app.register(channelRoutes, { db });
  await app.register(serverInfoRoutes, { db, config });
  await app.register(liveRoutes, { db });
  return app;
}
