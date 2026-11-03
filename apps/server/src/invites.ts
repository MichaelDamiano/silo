import type { Db } from './db.js';
import { hashSecret, randomSecret } from './secrets.js';

export async function createInvite(
  db: Db,
  opts: { createdBy: string | null; maxUses: number; expiresInHours: number },
): Promise<{ code: string; maxUses: number; expiresAt: Date }> {
  const code = randomSecret(18);
  const expiresAt = new Date(Date.now() + opts.expiresInHours * 3600_000);
  await db.query('INSERT INTO invites (code_hash, created_by, max_uses, expires_at) VALUES ($1, $2, $3, $4)', [
    hashSecret(code),
    opts.createdBy,
    opts.maxUses,
    expiresAt,
  ]);
  return { code, maxUses: opts.maxUses, expiresAt };
}
