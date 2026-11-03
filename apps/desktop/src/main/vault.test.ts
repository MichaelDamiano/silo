import { describe, expect, it } from 'vitest';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Vault } from './vault.js';
import type { SecretBox } from './keystore.js';

const box: SecretBox = {
  isAvailable: async () => true,
  encrypt: async (b) => Buffer.from(b.map((x) => x ^ 0x5a)),
  decrypt: async (b) => ({ plain: Buffer.from(b.map((x) => x ^ 0x5a)), shouldReEncrypt: false }),
};

describe('vault', () => {
  it('round-trips data and keeps it unreadable on disk', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'silo-vault-'));
    const v = await Vault.open(dir, box);
    await v.write('messages', { text: 'top secret' });
    expect((await readFile(path.join(dir, 'messages.enc'))).includes(Buffer.from('top secret'))).toBe(false);
    const again = await Vault.open(dir, box);
    expect(await again.read('messages')).toEqual({ text: 'top secret' });
    expect(await again.read('missing')).toBeNull();
  });

  it('detects tampering and swapped files', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'silo-vault-'));
    const v = await Vault.open(dir, box);
    await v.write('a', { n: 1 });
    await v.write('b', { n: 2 });
    const blob = await readFile(path.join(dir, 'a.enc'));
    blob[blob.length - 1]! ^= 1;
    await writeFile(path.join(dir, 'a.enc'), blob);
    await expect(v.read('a')).rejects.toThrow();
    await writeFile(path.join(dir, 'a.enc'), await readFile(path.join(dir, 'b.enc')));
    await expect(v.read('a')).rejects.toThrow();
  });
});
