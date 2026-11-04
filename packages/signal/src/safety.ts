import { createHash } from 'node:crypto';

const ITERATIONS = 5200;
const VERSION = Buffer.from([0, 0]);

/**
 * One side of a safety number: 30 digits derived from a person's id and the
 * identity keys of all their devices, the way Signal derives its numbers but over
 * every device instead of one account key.
 */
function half(userId: string, identityKeys: string[]): string {
  const keys = Buffer.concat([...identityKeys].sort().map((k) => Buffer.from(k, 'base64')));
  let hash = createHash('sha512').update(Buffer.concat([VERSION, keys, Buffer.from(userId, 'utf8')])).digest();
  for (let i = 1; i < ITERATIONS; i++) hash = createHash('sha512').update(Buffer.concat([hash, keys])).digest();
  let digits = '';
  for (let i = 0; i < 30; i += 5) digits += String(hash.readUIntBE(i, 5) % 100000).padStart(5, '0');
  return digits;
}

/**
 * The safety number two people compare to check that nobody, including the
 * server, slipped a device or key between them. Both sides get the same 60 digits,
 * and it changes whenever either person adds a device or a key changes.
 */
export function safetyNumber(a: { userId: string; identityKeys: string[] }, b: { userId: string; identityKeys: string[] }): string {
  const [x, y] = [half(a.userId, a.identityKeys), half(b.userId, b.identityKeys)].sort();
  return x! + y!;
}

/** Splits a safety number into twelve groups of five digits for reading aloud. */
export const formatSafetyNumber = (n: string) => n.match(/.{5}/g)!.join(' ');
