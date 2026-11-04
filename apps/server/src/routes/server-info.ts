import type { FastifyInstance } from 'fastify';
import { readFile, writeFile } from 'node:fs/promises';
import {
  Endpoint,
  fromBase64Url,
  generateDeviceKeyPair,
  publicKeyFromSecret,
  serverInfoPayload,
  sign,
  toBase64Url,
  type ServerInfo,
  type SignedServerInfo,
} from '@silo/protocol';
import { z } from 'zod';
import type { Config } from '../config.js';
import type { Db } from '../db.js';

/**
 * Loads the server's identity key, creating it on first start. With a key file the
 * secret lives only there (readable by the server alone), so a database dump or
 * backup can't be used to impersonate the server. A key that was in the database
 * is moved into the file the first time a file is configured.
 */
export async function serverIdentity(db: Db, keyFile?: string): Promise<{ publicKey: string; secretKey: Uint8Array }> {
  if (keyFile) return fileIdentity(db, keyFile);
  const kp = generateDeviceKeyPair();
  await db.query('INSERT INTO server_identity (public_key, secret_key) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING', [
    toBase64Url(kp.publicKey),
    toBase64Url(kp.secretKey),
  ]);
  const { rows } = await db.query<{ public_key: string; secret_key: string | null }>('SELECT public_key, secret_key FROM server_identity');
  if (!rows[0]!.secret_key) throw new Error('the server identity key was moved to a file; set SERVER_KEY_FILE');
  return { publicKey: rows[0]!.public_key, secretKey: fromBase64Url(rows[0]!.secret_key) };
}

async function fileIdentity(db: Db, keyFile: string) {
  const { rows } = await db.query<{ public_key: string; secret_key: string | null }>('SELECT public_key, secret_key FROM server_identity');
  let secret = (await readFile(keyFile, 'utf8').catch((e: NodeJS.ErrnoException) => (e.code === 'ENOENT' ? null : Promise.reject(e))))?.trim();
  if (!secret) {
    secret = rows[0]?.secret_key ?? toBase64Url(generateDeviceKeyPair().secretKey);
    // Fails rather than overwrites if another process created the file meanwhile.
    await writeFile(keyFile, secret + '\n', { mode: 0o600, flag: 'wx' });
  }
  const secretKey = fromBase64Url(secret);
  const publicKey = toBase64Url(publicKeyFromSecret(secretKey));
  if (rows[0] && rows[0].public_key !== publicKey) {
    throw new Error(`SERVER_KEY_FILE holds a different key than this server's identity; refusing to start`);
  }
  await db.query(
    `INSERT INTO server_identity (public_key, secret_key) VALUES ($1, NULL)
     ON CONFLICT (id) DO UPDATE SET secret_key = NULL`,
    [publicKey],
  );
  return { publicKey, secretKey };
}

/** The onion address Tor created for us, if Tor runs alongside the server. */
async function onionEndpoint(file?: string): Promise<string | undefined> {
  if (!file) return undefined;
  const host = (await readFile(file, 'utf8').catch(() => '')).trim();
  const parsed = Endpoint.safeParse(`http://${host}`);
  return parsed.success ? parsed.data : undefined;
}

/**
 * Tells clients every address this server can be reached at, signed with the
 * server's identity key. Clients pin that key the first time and use the list to
 * fail over when the address they normally use is blocked or down.
 */
export async function serverInfoRoutes(app: FastifyInstance, opts: { db: Db; config: Config }) {
  const identity = await serverIdentity(opts.db, opts.config.serverKeyFile);
  app.get('/v1/server-info', { config: { rateLimit: { max: 60, timeWindow: '1 minute' } } }, async (request): Promise<SignedServerInfo> => {
    const { nonce } = z.object({ nonce: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/) }).parse(request.query);
    const onion = await onionEndpoint(opts.config.onionHostnameFile);
    const endpoints = [...new Set([...opts.config.publicUrls, ...(onion ? [onion] : [])])];
    const info: ServerInfo = { v: 1, serverKey: identity.publicKey, endpoints, issuedAt: new Date().toISOString(), nonce };
    const text = JSON.stringify(info);
    return { info: text, signature: sign(serverInfoPayload(text), identity.secretKey) };
  });
}
