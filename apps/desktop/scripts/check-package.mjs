#!/usr/bin/env node
// Fails if a packaged Linux build (release/linux-unpacked) is missing a lockdown:
// a fuse left on, a source map or test file shipped, or code outside the archive.
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as asar from '@electron/asar';
import { FuseV1Options, getCurrentFuseWire } from '@electron/fuses';

const app = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'release', 'linux-unpacked');
const problems = [];

const want = {
  RunAsNode: false,
  EnableCookieEncryption: true,
  EnableNodeOptionsEnvironmentVariable: false,
  EnableNodeCliInspectArguments: false,
  EnableEmbeddedAsarIntegrityValidation: true,
  OnlyLoadAppFromAsar: true,
  LoadBrowserProcessSpecificV8Snapshot: false,
  GrantFileProtocolExtraPrivileges: false,
};
const wire = await getCurrentFuseWire(path.join(app, 'silo'));
for (const [name, on] of Object.entries(want)) {
  // The wire stores ASCII '1' (49) for on and '0' (48) for off.
  if (wire[FuseV1Options[name]] !== (on ? 49 : 48)) problems.push(`fuse ${name} should be ${on ? 'on' : 'off'}`);
}

const archive = path.join(app, 'resources', 'app.asar');
for (const f of asar.listPackage(archive)) {
  if (/\.map$|\.test\.[jt]s$|\.tsx?$/.test(f) && !f.endsWith('.d.ts') && !f.includes('/node_modules/')) problems.push(`ships ${f}`);
}
if (!asar.listPackage(archive).some((f) => f.replaceAll('\\', '/') === '/dist/main/main.js')) problems.push('no dist/main/main.js in app.asar');
const loose = readdirSync(path.join(app, 'resources')).filter((n) => !['app.asar', 'app.asar.unpacked'].includes(n));
if (loose.length) problems.push(`files outside the archive: ${loose.join(', ')}`);

if (problems.length) {
  console.error('Package check failed:\n  ' + problems.join('\n  '));
  process.exit(1);
}
console.log('Package check passed: fuses set, nothing extra shipped.');
