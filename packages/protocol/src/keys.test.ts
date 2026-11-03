import { describe, expect, it } from 'vitest';
import { fromBase64Url, toBase64Url } from './encoding.js';
import { generateDeviceKeyPair, loginPayload, sign, signupPayload, verify } from './keys.js';
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
    const sig = sign(signupPayload('n', 'mike'), kp.secretKey);
    expect(verify(sig, loginPayload('n'), pub)).toBe(false);
  });

  it('rejects fields containing newlines', () => {
    expect(() => signupPayload('n', 'a\nb')).toThrow();
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
