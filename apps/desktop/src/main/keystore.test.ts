import { describe, expect, it } from 'vitest';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadOrCreateDeviceKey, type SecretBox } from './keystore.js';
import { normalizeServerUrl } from './api.js';

// A stand-in for the OS keychain: XOR is enough to prove the plaintext never hits disk.
const fakeBox = (available = true): SecretBox => ({
  isAvailable: async () => available,
  encrypt: async (b) => Buffer.from(b.map((x) => x ^ 0xaa)),
  decrypt: async (b) => ({ plain: Buffer.from(b.map((x) => x ^ 0xaa)), shouldReEncrypt: false }),
});

describe('device key store', () => {
  it('creates a key once and loads the same key afterwards', async () => {
    const file = path.join(await mkdtemp(path.join(tmpdir(), 'silo-')), 'key.bin');
    const first = await loadOrCreateDeviceKey(file, fakeBox());
    const second = await loadOrCreateDeviceKey(file, fakeBox());
    expect(second.publicKey).toEqual(first.publicKey);
    const onDisk = await readFile(file);
    expect(Buffer.compare(onDisk, Buffer.from(first.secretKey))).not.toBe(0);
  });

  it('refuses to store a key without a keychain', async () => {
    const file = path.join(await mkdtemp(path.join(tmpdir(), 'silo-')), 'key.bin');
    await expect(loadOrCreateDeviceKey(file, fakeBox(false))).rejects.toThrow(/keychain/);
  });
});

describe('server address', () => {
  it('requires https except for localhost', () => {
    expect(normalizeServerUrl('https://chat.example.com/path')).toBe('https://chat.example.com');
    expect(normalizeServerUrl('http://localhost:8443')).toBe('http://localhost:8443');
    expect(() => normalizeServerUrl('http://chat.example.com')).toThrow(/https/);
    expect(() => normalizeServerUrl('https://user:pw@chat.example.com')).toThrow();
  });
});
