import { z } from 'zod';
import { PublicKey, Signature } from './api.js';

/**
 * An address the server can be reached at. Plain http is allowed only for Tor
 * onion services (Tor already encrypts and authenticates the connection) and for
 * this machine during development.
 */
export const Endpoint = z
  .string()
  .max(256)
  .refine((v) => {
    try {
      const u = new URL(v);
      if (u.username || u.password || u.pathname !== '/' || u.search || u.hash) return false;
      if (u.protocol === 'https:') return true;
      return u.protocol === 'http:' && (isOnion(u.hostname) || ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname));
    } catch {
      return false;
    }
  }, 'must be an https:// address, or http:// for a .onion or localhost address');

/** Tor v3 onion addresses are 56 base32 characters. */
export function isOnion(hostname: string): boolean {
  return /^[a-z2-7]{56}\.onion$/.test(hostname);
}

/** What the server signs. Sent as a JSON string so the client verifies exactly these bytes. */
export const ServerInfo = z.object({
  v: z.literal(1),
  serverKey: PublicKey,
  /** Every address the operator publishes, most preferred first. */
  endpoints: z.array(Endpoint).max(32),
  issuedAt: z.iso.datetime(),
  /** Echoes the client's nonce, so a recorded answer can't be replayed. */
  nonce: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/),
  /** The key that sender certificates chain to, for sealed sender (standard base64, a Curve25519 public key). */
  sealedSenderRoot: z.string().regex(/^[A-Za-z0-9+/]{44}$/).optional(),
});

export const SignedServerInfo = z.object({ info: z.string().max(16 * 1024), signature: Signature });

export type ServerInfo = z.infer<typeof ServerInfo>;
export type SignedServerInfo = z.infer<typeof SignedServerInfo>;
