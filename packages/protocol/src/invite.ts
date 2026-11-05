import { z } from 'zod';

const KEY = /^[A-Za-z0-9_-]{43}$/;
const CODE = /^[A-Za-z0-9_-]{16,64}$/;

/**
 * A sign-up invite that also names the server's identity key, so a new user's app
 * knows which server to trust before it ever connects. Without the key, the first
 * connection is trust on first use, and someone in between could pose as the server.
 *
 * Format: silo:<server key>:<code>[:<address>]
 */
export interface Invite {
  code: string;
  serverKey?: string;
  address?: string;
}

export function formatInvite(i: { code: string; serverKey: string; address?: string }): string {
  if (!CODE.test(i.code) || !KEY.test(i.serverKey)) throw new Error('bad invite parts');
  return `silo:${i.serverKey}:${i.code}${i.address ? `:${i.address}` : ''}`;
}

/** Reads a full invite, or a bare code from older invites. Throws on anything else. */
export function parseInvite(text: string): Invite {
  const t = text.trim();
  if (CODE.test(t)) return { code: t };
  const m = /^silo:([^:]+):([^:]+)(?::(.+))?$/.exec(t);
  if (!m || !KEY.test(m[1]!) || !CODE.test(m[2]!)) throw new Error('That doesn’t look like a Silo invite.');
  const address = m[3] && z.url({ protocol: /^https?$/ }).safeParse(m[3]).success ? m[3] : undefined;
  if (m[3] && !address) throw new Error('The server address in that invite isn’t valid.');
  return { code: m[2]!, serverKey: m[1]!, ...(address ? { address } : {}) };
}
