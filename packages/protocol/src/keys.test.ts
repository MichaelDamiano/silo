import { describe, expect, it } from 'vitest';
import { fromBase32, fromBase64Url, toBase32, toBase64Url } from './encoding.js';
import {
  fingerprint,
  formatRecoveryKey,
  generateDeviceKeyPair,
  loginPayload,
  parseRecoveryKey,
  sign,
  signupPayload,
  verify,
} from './keys.js';
import { PublicKey, Signature } from './api.js';

describe('device keys', () => {
  it('signs and verifies', () => {
    const kp = generateDeviceKeyPair();
    const pub = toBase64Url(kp.publicKey);
    const sig = sign(loginPayload('abc'), kp.secretKey);
    expect(PublicKey.safeParse(pub).success).toBe(true);
    expect(Signature.safeParse(sig).success).toBe(true);
    expect(verify(sig, loginPayload('abc'), pub)).toBe(true);
    expect(verify(sig, loginPayload('abd'), pub)).toBe(false);
  });

  it('keeps signatures for different purposes apart', () => {
    const kp = generateDeviceKeyPair();
    const pub = toBase64Url(kp.publicKey);
    const sig = sign(signupPayload('n', 'mike', 'r'), kp.secretKey);
    expect(verify(sig, loginPayload('n'), pub)).toBe(false);
  });

  it('rejects fields containing newlines', () => {
    expect(() => signupPayload('n', 'a\nb', 'r')).toThrow();
  });

  it('round-trips base64url', () => {
    const bytes = new Uint8Array([0, 255, 62, 63, 128]);
    expect(fromBase64Url(toBase64Url(bytes))).toEqual(bytes);
    expect(() => fromBase64Url('not+valid')).toThrow();
  });

  it('returns false for malformed keys instead of throwing', () => {
    expect(verify('x'.repeat(86), loginPayload('n'), 'y'.repeat(43))).toBe(false);
  });
});

describe('recovery keys and fingerprints', () => {
  it('round-trips a recovery key through its printed form', () => {
    const kp = generateDeviceKeyPair();
    const printed = formatRecoveryKey(kp.secretKey);
    expect(printed).toMatch(/^([A-Z2-7]{4}-){12}[A-Z2-7]{4}$/);
    expect(parseRecoveryKey(printed.toLowerCase().replace(/-/g, ' '))).toEqual(kp.secretKey);
    expect(() => parseRecoveryKey('ABCD-EFGH')).toThrow(/length/);
  });

  it('round-trips arbitrary bytes through base32', () => {
    for (let n = 0; n < 40; n++) {
      const bytes = crypto.getRandomValues(new Uint8Array(n));
      expect(fromBase32(toBase32(bytes))).toEqual(bytes);
    }
    expect(toBase32(new TextEncoder().encode('foobar'))).toBe('MZXW6YTBOI');
  });

  it('gives a stable, short fingerprint', () => {
    const pub = toBase64Url(generateDeviceKeyPair().publicKey);
    expect(fingerprint(pub)).toMatch(/^[0-9A-F]{4}( [0-9A-F]{4}){3}$/);
    expect(fingerprint(pub)).toBe(fingerprint(pub));
  });
});
