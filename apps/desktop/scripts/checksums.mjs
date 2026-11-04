#!/usr/bin/env node
// Writes release/SHA256SUMS-<os>.txt: a hash for every release file, plus one for
// the app.asar inside it, which is what `npm run verify-release` rebuilds and compares.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'release');
const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
const lines = [];
for (const name of readdirSync(dir).sort()) {
  const p = path.join(dir, name);
  if (statSync(p).isFile() && /\.(AppImage|tar\.gz|dmg|zip|exe)$/.test(name)) lines.push(`${sha256(p)}  ${name}`);
}
const findAsar = (d) => {
  for (const e of readdirSync(d, { withFileTypes: true })) {
    const p = path.join(d, e.name);
    if (e.isFile() && e.name === 'app.asar') return p;
    if (e.isDirectory() && !e.name.endsWith('.unpacked')) {
      const hit = findAsar(p);
      if (hit) return hit;
    }
  }
};
const asar = findAsar(dir);
if (asar) lines.push(`${sha256(asar)}  app.asar (${process.platform})`);
const out = path.join(dir, `SHA256SUMS-${process.platform}.txt`);
writeFileSync(out, lines.join('\n') + '\n');
console.log(lines.join('\n'));
