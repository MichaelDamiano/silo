#!/usr/bin/env node
// Creates the Ed25519 key that signs Silo updates, and builds its public half into the app.
//
//   npm run release-key -w @silo/desktop -- [where to save the private key]
//
// The private key is saved encrypted with a passphrase you choose. Keep it, and a
// backup, off any machine that builds or hosts releases: whoever has it and the
// passphrase can push updates to every Silo install.
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { askSecret, CONFIG, trustedKeys } from './release-common.mjs';

const out = path.resolve(process.argv[2] ?? path.join(homedir(), 'silo-release-key.pem'));
if (existsSync(out)) {
  console.error(`${out} already exists. Pick another path; this never overwrites a key.`);
  process.exit(1);
}
const pass = await askSecret('Passphrase for the new release key (12+ characters): ');
if (pass.length < 12) {
  console.error('Use at least 12 characters.');
  process.exit(1);
}
if ((await askSecret('Type it again: ')) !== pass) {
  console.error("The passphrases don't match.");
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'der' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: pass },
});
writeFileSync(out, privateKey, { mode: 0o600, flag: 'wx' });
const raw = publicKey.subarray(-32).toString('base64');

const keys = [...trustedKeys(), raw];
const src = readFileSync(CONFIG, 'utf8').replace(
  /UPDATE_KEYS: string\[\] = \[[^\]]*\]/,
  `UPDATE_KEYS: string[] = [\n${keys.map((k) => `  '${k}',`).join('\n')}\n]`,
);
writeFileSync(CONFIG, src);

console.log(`\nPrivate key saved to ${out}`);
console.log(`Public key ${raw} added to src/main/update-config.ts.`);
console.log('\nNext: back the private key up somewhere offline (a USB stick), then commit update-config.ts.');
console.log('Builds made after that commit accept updates signed with this key.');
