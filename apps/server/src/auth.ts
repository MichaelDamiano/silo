import type { FastifyReply, FastifyRequest } from 'fastify';
import type pg from 'pg';
import type { Db } from './db.js';
import { authFailed } from './errors.js';
import { hashSecret, randomSecret } from './secrets.js';

export interface AuthContext {
  userId: string;
  deviceId: string;
  sessionId: string;
}

declare module 'fastify' {
  interface FastifyRequest {
    auth?: AuthContext;
  }
}

export async function createSession(
  client: pg.PoolClient | Db,
  deviceId: string,
  ttlMs: number,
): Promise<{ token: string; expiresAt: Date }> {
  const token = randomSecret();
  const expiresAt = new Date(Date.now() + ttlMs);
  await client.query('INSERT INTO sessions (token_hash, device_id, expires_at) VALUES ($1, $2, $3)', [
    hashSecret(token),
    deviceId,
    expiresAt,
  ]);
  return { token, expiresAt };
}

/** preHandler that requires a valid, unexpired session on a device that is not revoked. */
export function requireAuth(db: Db) {
  return async (request: FastifyRequest, _reply: FastifyReply) => {
    const header = request.headers.authorization;
    const match = header?.match(/^Bearer ([A-Za-z0-9_-]{43})$/);
    if (!match?.[1]) throw authFailed();
    const { rows } = await db.query<{ session_id: string; device_id: string; user_id: string }>(
      `SELECT s.id AS session_id, d.id AS device_id, d.user_id
         FROM sessions s JOIN devices d ON d.id = s.device_id
        WHERE s.token_hash = $1
          AND s.revoked_at IS NULL AND s.expires_at > now()
          AND d.revoked_at IS NULL`,
      [hashSecret(match[1])],
    );
    const row = rows[0];
    if (!row) throw authFailed();
    request.auth = { userId: row.user_id, deviceId: row.device_id, sessionId: row.session_id };
  };
}
