import { createHash, randomBytes } from 'node:crypto';
import { toBase64Url } from '@silo/protocol';

/** A random 256-bit secret, base64url encoded. */
export function randomSecret(bytes = 32): string {
  return toBase64Url(randomBytes(bytes));
}

/** Tokens and invite codes are only ever stored hashed. */
export function hashSecret(secret: string): Buffer {
  return createHash('sha256').update(secret, 'utf8').digest();
}
