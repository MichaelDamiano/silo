import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { SecretBox } from './keystore.js';

/**
 * Encrypted JSON files on disk. One random data key encrypts every file with
 * AES-256-GCM, and that key is itself sealed by the OS keychain.
 */
export class Vault {
  private constructor(
    private readonly dir: string,
    private readonly key: Buffer,
  ) {}

  static async open(dir: string, box: SecretBox): Promise<Vault> {
    if (!(await box.isAvailable())) throw new Error('No OS keychain is available to protect local data.');
    const keyFile = path.join(dir, 'vault-key.bin');
    let key: Buffer | undefined;
    try {
      key = (await box.decrypt(await readFile(keyFile))).plain;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
    }
    if (!key) {
      key = randomBytes(32);
      await atomicWrite(keyFile, await box.encrypt(key));
    }
    if (key.length !== 32) throw new Error('Local data key is corrupt.');
    return new Vault(dir, key);
  }

  async read<T>(name: string): Promise<T | null> {
    let blob: Buffer;
    try {
      blob = await readFile(this.file(name));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
      throw err;
    }
    // Layout: 1 version byte, 12-byte nonce, 16-byte tag, then ciphertext.
    if (blob[0] !== 1) throw new Error(`unknown vault format in ${name}`);
    const decipher = createDecipheriv('aes-256-gcm', this.key, blob.subarray(1, 13));
    decipher.setAAD(Buffer.from(name));
    decipher.setAuthTag(blob.subarray(13, 29));
    const plain = Buffer.concat([decipher.update(blob.subarray(29)), decipher.final()]);
    return JSON.parse(plain.toString('utf8')) as T;
  }

  async write(name: string, value: unknown): Promise<void> {
    const nonce = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, nonce);
    // Binding the file name stops one encrypted file being swapped in for another.
    cipher.setAAD(Buffer.from(name));
    const body = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
    await atomicWrite(this.file(name), Buffer.concat([Buffer.from([1]), nonce, cipher.getAuthTag(), body]));
  }

  private file(name: string) {
    if (!/^[a-z0-9-]+$/.test(name)) throw new Error('bad vault file name');
    return path.join(this.dir, `${name}.enc`);
  }
}

async function atomicWrite(file: string, data: Buffer) {
  const tmp = `${file}.${process.pid}.tmp`;
  await writeFile(tmp, data, { mode: 0o600 });
  await rename(tmp, file);
}
