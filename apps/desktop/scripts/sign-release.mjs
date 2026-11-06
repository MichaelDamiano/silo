#!/usr/bin/env node
// Signs a release so installed copies of Silo will update to it.
//
//   npm run sign-release -w @silo/desktop -- <SHA256SUMS.txt> <version> [--key <file>] [--notes "<text>"]
//
// Download SHA256SUMS.txt from the draft GitHub release, run this, then upload the
// silo-update.json it writes to the same draft and publish it. The app only accepts
// files whose hashes are in a manifest signed by a key listed in update-config.ts.
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { askSecret, trustedKeys } from './release-common.mjs';

const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  if (i < 0) return undefined;
  const v = args[i + 1];
  args.splice(i, 2);
  return v;
};
const keyFile = path.resolve(opt('--key') ?? path.join(homedir(), 'silo-release-key.pem'));
const notes = opt('--notes');
const [sumsFile, versionArg] = args;
if (!sumsFile || !versionArg) {
  console.error('usage: npm run sign-release -w @silo/desktop -- <SHA256SUMS.txt> <version> [--key <file>] [--notes "<text>"]');
  process.exit(2);
}
const version = versionArg.replace(/^v/, '');
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(`"${versionArg}" isn't a version like 0.2.0`);
  process.exit(2);
}

const files = [];
for (const line of readFileSync(sumsFile, 'utf8').split(/\r?\n/)) {
  // Release files only; the "app.asar (platform)" lines are for verify-release.
  const m = /^([0-9a-f]{64}) {2}([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(line.trim());
  if (m) files.push({ name: m[2], sha256: m[1] });
}
if (!files.some((f) => f.name.includes(`-${version}-`))) {
  console.error(`No file for version ${version} in ${sumsFile}. Is the version right?`);
  process.exit(1);
}
const stray = files.filter((f) => !f.name.includes(`-${version}-`));
if (stray.length) {
  console.error(`These files are for another version: ${stray.map((f) => f.name).join(', ')}`);
  process.exit(1);
}

const payload = Buffer.from(
  JSON.stringify({ app: 'silo-desktop', version, released: new Date().toISOString(), ...(notes ? { notes } : {}), files }),
);
let key;
try {
  key = createPrivateKey({ key: readFileSync(keyFile), passphrase: await askSecret(`Passphrase for ${keyFile}: `) });
} catch (err) {
  console.error(err?.code === 'ENOENT' ? `No key at ${keyFile}. Pass --key <file>.` : 'Wrong passphrase, or that file is not a release key.');
  process.exit(1);
}
const signature = sign(null, payload, key);

const mine = createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64');
if (!trustedKeys().includes(mine)) {
  console.error(`This key (${mine}) isn't in src/main/update-config.ts, so the app would reject the update.`);
  process.exit(1);
}
if (!verify(null, payload, createPublicKey(key), signature)) throw new Error('signature check failed');

const out = path.join(path.dirname(path.resolve(sumsFile)), 'silo-update.json');
writeFileSync(out, JSON.stringify({ payload: payload.toString('base64'), signature: signature.toString('base64') }, null, 2) + '\n');
console.log(`Signed Silo ${version} (${files.length} files):`);
for (const f of files) console.log(`  ${f.sha256}  ${f.name}`);
console.log(`\nWrote ${out}. Upload it to the draft release, then publish the release.`);
