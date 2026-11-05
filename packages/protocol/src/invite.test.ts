import { describe, expect, it } from 'vitest';
import { formatInvite, parseInvite } from './invite.js';

const serverKey = 'A'.repeat(43);
const code = 'abcdefghijklmnopqrstuv';

describe('invites', () => {
  it('round-trips a full invite, with or without an address', () => {
    expect(parseInvite(formatInvite({ code, serverKey, address: 'https://chat.example.org:8443' }))).toEqual({
      code,
      serverKey,
      address: 'https://chat.example.org:8443',
    });
    expect(parseInvite(` ${formatInvite({ code, serverKey })} `)).toEqual({ code, serverKey });
    expect(parseInvite(formatInvite({ code, serverKey, address: 'http://abc.onion' })).address).toBe('http://abc.onion');
  });

  it('still accepts a bare code', () => {
    expect(parseInvite(code)).toEqual({ code });
  });

  it('rejects anything malformed', () => {
    for (const bad of ['silo:short:' + code, `silo:${serverKey}:x`, `silo:${serverKey}:${code}:javascript:alert(1)`, 'hello', '']) {
      expect(() => parseInvite(bad)).toThrow();
    }
  });
});
