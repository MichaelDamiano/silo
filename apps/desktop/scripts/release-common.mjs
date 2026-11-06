// Shared by release-key.mjs and sign-release.mjs.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const CONFIG = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'main', 'update-config.ts');

/** The public keys the app trusts, read from update-config.ts. */
export function trustedKeys() {
  const m = /UPDATE_KEYS: string\[\] = \[([^\]]*)\]/.exec(readFileSync(CONFIG, 'utf8'));
  if (!m) throw new Error(`Couldn't find UPDATE_KEYS in ${CONFIG}`);
  return [...m[1].matchAll(/'([A-Za-z0-9+/=]+)'/g)].map((x) => x[1]);
}

/** Asks for a passphrase without echoing it. SILO_RELEASE_PASSPHRASE skips the prompt. */
export function askSecret(question) {
  if (process.env.SILO_RELEASE_PASSPHRASE) return Promise.resolve(process.env.SILO_RELEASE_PASSPHRASE);
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) return reject(new Error('Run this in a terminal, or set SILO_RELEASE_PASSPHRASE.'));
    process.stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let value = '';
    const onData = (ch) => {
      for (const c of ch) {
        if (c === '\r' || c === '\n') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off('data', onData);
          process.stdout.write('\n');
          return resolve(value);
        }
        if (c === '\u0003') {
          process.stdout.write('\n');
          process.exit(130);
        }
        if (c === '\u0008' || c === '\u007f') value = value.slice(0, -1);
        else value += c;
      }
    };
    stdin.on('data', onData);
  });
}
