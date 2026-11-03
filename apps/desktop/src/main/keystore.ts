import { readFile, writeFile, rename } from 'node:fs/promises';
import { generateDeviceKeyPair, publicKeyFromSecret, type DeviceKeyPair } from '@silo/protocol';

/** Encrypts data with a key held by the operating system (Keychain, DPAPI, or libsecret). */
export interface SecretBox {
  isAvailable(): Promise<boolean>;
  encrypt(plain: Buffer): Promise<Buffer>;
  decrypt(sealed: Buffer): Promise<{ plain: Buffer; shouldReEncrypt: boolean }>;
}

/**
 * Loads this device's identity key, creating it on first run. The secret key is
 * only ever written to disk encrypted by the OS keychain; if no keychain is
 * available we refuse to store it rather than fall back to plaintext.
 */
export async function loadOrCreateDeviceKey(file: string, box: SecretBox): Promise<DeviceKeyPair> {
  if (!(await box.isAvailable())) throw new Error('No OS keychain is available to protect the device key.');
  let sealed: Buffer | undefined;
  try {
    sealed = await readFile(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }
  if (sealed) {
    const { plain, shouldReEncrypt } = await box.decrypt(sealed);
    const secretKey = new Uint8Array(plain);
    if (secretKey.length !== 32) throw new Error('Stored device key is corrupt.');
    // The keychain rotated its key: store the device key again under the new one.
    if (shouldReEncrypt) await save(file, box, secretKey);
    return { secretKey, publicKey: publicKeyFromSecret(secretKey) };
  }
  const pair = generateDeviceKeyPair();
  await save(file, box, pair.secretKey);
  return pair;
}

async function save(file: string, box: SecretBox, secretKey: Uint8Array) {
  const tmp = `${file}.tmp`;
  await writeFile(tmp, await box.encrypt(Buffer.from(secretKey)), { mode: 0o600 });
  await rename(tmp, file);
}
