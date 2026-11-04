import type { FastifyRequest } from 'fastify';
import type { Db } from './db.js';
import { hashSecret } from './secrets.js';
import { HttpError } from './errors.js';

/** Hard caps that stop one account from filling the server or flooding others. */
export const LIMITS = {
  /** Older sessions on the same device are revoked once there are more than this. */
  sessionsPerDevice: 5,
  /** Unused, unexpired sign-up codes one person can have out at a time. */
  activeInvitesPerUser: 10,
  /** Servers one account can be a member of. */
  spacesPerUser: 200,
  /** Undelivered messages waiting for one device before senders are told its mailbox is full. */
  pendingEnvelopesPerDevice: 5000,
} as const;

/** Refuses a send if any recipient device already has a full mailbox, so a flood can't fill the database. */
export async function requireMailboxRoom(db: Db, deviceIds: string[]) {
  const { rows } = await db.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM envelopes WHERE recipient_device = ANY($1::uuid[]) GROUP BY recipient_device ORDER BY 1 DESC LIMIT 1`,
    [deviceIds],
  );
  if ((rows[0]?.n ?? 0) >= LIMITS.pendingEnvelopesPerDevice) {
    throw new HttpError(429, "a recipient's device has too many undelivered messages; try again later");
  }
}

/** Request size caps. Each copy of a message fits a full 4000-character text with room to spare. */
export const BODY_LIMITS = {
  directMessage: 3 * 1024 * 1024,
  channelMessage: 64 * 1024,
  senderKeys: 2 * 1024 * 1024,
} as const;

const CACHE_MS = 60_000;
const CACHE_MAX = 10_000;

/**
 * Rate limit signed-in requests per account rather than per session or IP. Otherwise
 * someone could get a fresh allowance just by signing in again, while people who
 * share an IP (a family, an office, Tor) would block each other.
 */
export function perUserLimit(db: Db) {
  const cache = new Map<string, { key: string; at: number }>();
  const keyGenerator = async (req: FastifyRequest): Promise<string> => {
    const token = req.headers.authorization?.match(/^Bearer ([A-Za-z0-9_-]{43})$/)?.[1];
    if (!token) return `ip:${req.ip}`;
    const hash = hashSecret(token).toString('hex');
    const hit = cache.get(hash);
    if (hit && Date.now() - hit.at < CACHE_MS) return hit.key;
    const { rows } = await db.query<{ user_id: string }>(
      `SELECT d.user_id FROM sessions s JOIN devices d ON d.id = s.device_id
        WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND d.revoked_at IS NULL`,
      [hashSecret(token)],
    );
    // An unknown token gets the IP's allowance; auth rejects the request anyway.
    const key = rows[0] ? `user:${rows[0].user_id}` : `ip:${req.ip}`;
    if (cache.size >= CACHE_MAX) cache.clear();
    cache.set(hash, { key, at: Date.now() });
    return key;
  };
  return (max: number, timeWindow: string) => ({ rateLimit: { max, timeWindow, keyGenerator } });
}
