import { ed25519 } from '@noble/curves/ed25519.js';
import { fromBase64Url, toBase64Url } from './encoding.js';

/**
 * Each device has its own Ed25519 identity key. The secret key never leaves
 * the device; the server only ever sees the public key.
 */
export interface DeviceKeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateDeviceKeyPair(): DeviceKeyPair {
  const secretKey = ed25519.utils.randomSecretKey();
  return { secretKey, publicKey: ed25519.getPublicKey(secretKey) };
}

export function publicKeyFromSecret(secretKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(secretKey);
}

const encoder = new TextEncoder();

/**
 * Every signed payload starts with a fixed context string, so a signature made
 * for one purpose can never be replayed as another (domain separation).
 */
export const SIGNING_CONTEXT = {
  signup: 'silo/v1/signup',
  login: 'silo/v1/login',
} as const;

export type SigningPurpose = keyof typeof SIGNING_CONTEXT;

export function signingPayload(purpose: SigningPurpose, fields: string[]): Uint8Array {
  for (const f of fields) {
    if (f.includes('\n')) throw new Error('signed fields must not contain newlines');
  }
  return encoder.encode([SIGNING_CONTEXT[purpose], ...fields].join('\n'));
}

export function signupPayload(nonce: string, username: string): Uint8Array {
  return signingPayload('signup', [nonce, username]);
}

export function loginPayload(nonce: string): Uint8Array {
  return signingPayload('login', [nonce]);
}

export function sign(payload: Uint8Array, secretKey: Uint8Array): string {
  return toBase64Url(ed25519.sign(payload, secretKey));
}

export function verify(signature: string, payload: Uint8Array, publicKey: string): boolean {
  try {
    return ed25519.verify(fromBase64Url(signature), payload, fromBase64Url(publicKey));
  } catch {
    return false;
  }
}
