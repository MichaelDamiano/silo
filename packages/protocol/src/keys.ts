import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { fromBase32, fromBase64Url, toBase32, toBase64Url } from './encoding.js';

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
  linkRequest: 'silo/v1/link-request',
  linkApprove: 'silo/v1/link-approve',
  recover: 'silo/v1/recover',
  rotateRecovery: 'silo/v1/rotate-recovery',
  signalIdentity: 'silo/v1/signal-identity',
} as const;

export type SigningPurpose = keyof typeof SIGNING_CONTEXT;

export function signingPayload(purpose: SigningPurpose, fields: string[]): Uint8Array {
  for (const f of fields) {
    if (f.includes('\n')) throw new Error('signed fields must not contain newlines');
  }
  return encoder.encode([SIGNING_CONTEXT[purpose], ...fields].join('\n'));
}

export function signupPayload(nonce: string, username: string, recoveryPublicKey: string): Uint8Array {
  return signingPayload('signup', [nonce, username, recoveryPublicKey]);
}

/** Signed by a new device asking to join an existing account. */
export function linkRequestPayload(nonce: string, username: string, deviceName: string): Uint8Array {
  return signingPayload('linkRequest', [nonce, username, deviceName]);
}

/** Signed by an existing device to vouch for a new device's key. */
export function linkApprovePayload(linkId: string, newDevicePublicKey: string): Uint8Array {
  return signingPayload('linkApprove', [linkId, newDevicePublicKey]);
}

/** Signed by both the recovery key and the new device during account recovery. */
export function recoverPayload(nonce: string, username: string, newDevicePublicKey: string): Uint8Array {
  return signingPayload('recover', [nonce, username, newDevicePublicKey]);
}

/** Signed by the new recovery key, proving the client holds it. */
export function rotateRecoveryPayload(userId: string, recoveryPublicKey: string): Uint8Array {
  return signingPayload('rotateRecovery', [userId, recoveryPublicKey]);
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

/** Signed by a device's login key to vouch for its Signal identity key (base64). */
export function signalIdentityPayload(deviceId: string, signalIdentityKey: string): Uint8Array {
  return signingPayload('signalIdentity', [deviceId, signalIdentityKey]);
}

/**
 * A short, human-comparable fingerprint of a public key, such as "3F2A 9C1E 5B7D 4E8A".
 * Users compare it on both screens before approving a new device.
 */
export function fingerprint(publicKey: string): string {
  const hex = Array.from(sha256(fromBase64Url(publicKey)).slice(0, 8), (b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  return hex.match(/.{4}/g)!.join(' ');
}

/**
 * The recovery key is a separate Ed25519 key the user writes down at sign-up.
 * It is shown as grouped base32 so it can be typed back in.
 */
export function formatRecoveryKey(secretKey: Uint8Array): string {
  return toBase32(secretKey).match(/.{1,4}/g)!.join('-');
}

export function parseRecoveryKey(text: string): Uint8Array {
  const bytes = fromBase32(text.replace(/[\s-]/g, '').toUpperCase());
  if (bytes.length !== 32) throw new Error('That recovery key is not the right length.');
  return bytes;
}
