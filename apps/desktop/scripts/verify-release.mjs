#!/usr/bin/env node
// Checks that a Silo release contains exactly the code in this checkout.
//
//   npm run dist -w @silo/desktop                      # build it yourself first
//   npm run verify-release -w @silo/desktop -- <release>
//
// <release> is a downloaded .tar.gz or .zip, an unpacked app folder, or the
// app.asar from an installed copy. It compares the app archive and the native
// modules next to it, file by file, with your own build in release/.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as asar from '@electron/asar';

const here = path.dirname(fileURLToPath(import.meta.url));
const releaseDir = path.join(here, '..', 'release');

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function findAsar(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, entry.name);
    if (entry.isFile() && entry.name === 'app.asar') return p;
    if (entry.isDirectory() && !entry.name.endsWith('.asar.unpacked')) {
      const hit = findAsar(p);
      if (hit) return hit;
    }
  }
  return undefined;
}

/** Every file in an app: the archive's contents plus the unpacked native modules beside it. */
function inventory(asarPath) {
  const files = new Map();
  const header = asar.getRawHeader(asarPath).header;
  const walk = (node, prefix) => {
    for (const [name, child] of Object.entries(node.files ?? {})) {
      const p = prefix ? `${prefix}/${name}` : name;
      if (child.files) walk(child, p);
      else if (child.link) files.set(p, `link:${child.link}`);
      else if (child.unpacked) {
        const real = path.join(`${asarPath}.unpacked`, ...p.split('/'));
        files.set(p, existsSync(real) ? sha256(readFileSync(real)) : 'missing');
      } else files.set(p, sha256(asar.extractFile(asarPath, p)));
    }
  };
  walk(header, '');
  return files;
}

function openRelease(input) {
  const abs = path.resolve(input);
  if (!existsSync(abs)) throw new Error(`${input} doesn't exist`);
  if (statSync(abs).isDirectory()) return { asarPath: findAsar(abs), cleanup() {} };
  if (abs.endsWith('.asar')) return { asarPath: abs, cleanup() {} };
  const tmp = mkdtempSync(path.join(tmpdir(), 'silo-verify-'));
  // Only extract archives; never run anything from the download.
  if (abs.endsWith('.tar.gz') || abs.endsWith('.tgz')) execFileSync('tar', ['-xzf', abs, '-C', tmp, '--no-same-owner']);
  else if (abs.endsWith('.zip')) execFileSync('unzip', ['-q', abs, '-d', tmp]);
  else throw new Error('Give a .tar.gz, .zip, an unpacked folder or an app.asar. For an AppImage, .dmg or installer, install it and pass its resources/app.asar.');
  return { asarPath: findAsar(tmp), cleanup: () => rmSync(tmp, { recursive: true, force: true }) };
}

const target = process.argv[2];
if (!target) {
  console.error('usage: npm run verify-release -w @silo/desktop -- <release .tar.gz | .zip | folder | app.asar>');
  process.exit(2);
}
const mine = existsSync(releaseDir) ? findAsar(releaseDir) : undefined;
if (!mine) {
  console.error('No local build found. Run `npm ci && npm run dist -w @silo/desktop` from this checkout first.');
  process.exit(2);
}

const theirs = openRelease(target);
try {
  if (!theirs.asarPath) throw new Error('no app.asar in that release');
  const a = inventory(mine);
  const b = inventory(theirs.asarPath);
  const diffs = [];
  for (const p of new Set([...a.keys(), ...b.keys()])) {
    if (a.get(p) !== b.get(p)) diffs.push(`${!a.has(p) ? 'only in release' : !b.has(p) ? 'only in your build' : 'differs'}: ${p}`);
  }
  console.log(`your build: ${sha256(readFileSync(mine))}  ${path.relative(process.cwd(), mine)}`);
  console.log(`release:    ${sha256(readFileSync(theirs.asarPath))}  ${target}`);
  if (diffs.length) {
    console.log(`\nMISMATCH: ${diffs.length} file(s) differ.`);
    for (const d of diffs.slice(0, 50)) console.log('  ' + d);
    process.exit(1);
  }
  console.log(`\nOK: all ${a.size} files match your build.`);
} finally {
  theirs.cleanup();
}
