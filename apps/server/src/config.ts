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
  };
}
