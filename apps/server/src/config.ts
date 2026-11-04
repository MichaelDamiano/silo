import { Endpoint } from '@silo/protocol';

export interface Config {
  databaseUrl: string;
  port: number;
  host: string;
  /** How long a session token stays valid. */
  sessionTtlMs: number;
  /** How long a device has to sign a challenge. */
  challengeTtlMs: number;
  /** Trust X-Forwarded-For. Only enable behind your own reverse proxy. */
  trustProxy: boolean;
  /** Sign-up, login and challenge requests allowed per IP per minute. */
  authRateLimitPerMinute: number;
  /** Addresses this server publishes for clients to fall back to, most preferred first. */
  publicUrls: string[];
  /** Where Tor writes this server's onion hostname, so it can be published automatically. */
  onionHostnameFile?: string;
  /** Where the server's identity secret key is kept. Without it the key stays in the database (fine for development). */
  serverKeyFile?: string;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const databaseUrl = env.DATABASE_URL;
  if (!databaseUrl) throw new Error('DATABASE_URL is required');
  return {
    databaseUrl,
    port: Number(env.PORT ?? 8443),
    host: env.HOST ?? '127.0.0.1',
    sessionTtlMs: Number(env.SESSION_TTL_HOURS ?? 24 * 30) * 3600_000,
    challengeTtlMs: 60_000,
    trustProxy: env.TRUST_PROXY === 'true',
    authRateLimitPerMinute: Number(env.AUTH_RATE_LIMIT_PER_MINUTE ?? 10),
    publicUrls: (env.PUBLIC_URLS ?? '')
      .split(',')
      .map((u) => u.trim())
      .filter(Boolean)
      .map((u) => {
        const parsed = Endpoint.safeParse(new URL(u).origin);
        if (!parsed.success) throw new Error(`PUBLIC_URLS: ${u} ${parsed.error.issues[0]?.message}`);
        return parsed.data;
      }),
    onionHostnameFile: env.ONION_HOSTNAME_FILE || undefined,
    serverKeyFile: env.SERVER_KEY_FILE || undefined,
  };
}
