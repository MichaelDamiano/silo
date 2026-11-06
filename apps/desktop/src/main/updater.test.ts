import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { UpdateView } from '../shared/ipc.js';
import { installerFor, isNewer, Updater, verifyManifest } from './updater.js';

function keyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { privateKey, raw: publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64') };
}

function signed(payload: object, key: KeyObject) {
  const bytes = Buffer.from(JSON.stringify(payload));
  return { payload: bytes.toString('base64'), signature: sign(null, bytes, key).toString('base64') };
}

const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const release = (version: string, files: { name: string; sha256: string }[]) => ({ app: 'silo-desktop', version, released: '2026-11-06', files });

describe('verifyManifest', () => {
  const k = keyPair();
  const m = release('0.2.0', [{ name: 'silo-0.2.0-win-x64.exe', sha256: 'a'.repeat(64) }]);

  it('accepts a manifest signed by a trusted key', () => {
    expect(verifyManifest(signed(m, k.privateKey), [k.raw]).version).toBe('0.2.0');
  });

  it('rejects a manifest signed by another key', () => {
    const other = keyPair();
    expect(() => verifyManifest(signed(m, other.privateKey), [k.raw])).toThrow(/not signed/);
  });

  it('rejects a payload changed after signing', () => {
    const env = signed(m, k.privateKey);
    const tampered = Buffer.from(JSON.stringify({ ...m, files: [{ name: 'silo-0.2.0-win-x64.exe', sha256: 'b'.repeat(64) }] }));
    expect(() => verifyManifest({ ...env, payload: tampered.toString('base64') }, [k.raw])).toThrow(/not signed/);
  });

  it('refuses everything when the build has no key', () => {
    expect(() => verifyManifest(signed(m, k.privateKey), [])).toThrow(/no update key/);
  });

  it('rejects file names that could escape the download folder', () => {
    const bad = release('0.2.0', [{ name: '../../evil.exe', sha256: 'a'.repeat(64) }]);
    expect(() => verifyManifest(signed(bad, k.privateKey), [k.raw])).toThrow();
  });
});

describe('versions and files', () => {
  it('compares versions numerically', () => {
    expect(isNewer('0.10.0', '0.9.9')).toBe(true);
    expect(isNewer('0.2.0', '0.2.0')).toBe(false);
    expect(isNewer('0.1.9', '0.2.0')).toBe(false);
  });

  it('installs only the Windows installer for this architecture', () => {
    const m = release('0.2.0', [
      { name: 'silo-0.2.0-win-x64.exe', sha256: 'a'.repeat(64) },
      { name: 'silo-0.2.0-linux-x86_64.AppImage', sha256: 'b'.repeat(64) },
    ]);
    expect(installerFor(m, 'win32', 'x64')?.name).toBe('silo-0.2.0-win-x64.exe');
    expect(installerFor(m, 'win32', 'arm64')).toBeUndefined();
    expect(installerFor(m, 'linux', 'x64')).toBeUndefined();
  });
});

describe('Updater', () => {
  const dirs: string[] = [];
  afterEach(() => dirs.splice(0).forEach((d) => rmSync(d, { recursive: true, force: true })));

  function setup(opts: { version?: string; installer?: Buffer; served?: Buffer; platform?: string }) {
    const k = keyPair();
    const dir = mkdtempSync(path.join(tmpdir(), 'silo-upd-'));
    dirs.push(dir);
    const version = opts.version ?? '0.2.0';
    const installer = opts.installer ?? Buffer.from('installer bytes');
    const name = `silo-${version}-win-x64.exe`;
    const manifest = signed(release(version, [{ name, sha256: sha(installer) }]), k.privateKey);
    const fetched: string[] = [];
    const launched: string[] = [];
    const views: UpdateView[] = [];
    const u = new Updater({
      currentVersion: '0.1.0',
      platform: opts.platform ?? 'win32',
      arch: 'x64',
      feed: 'https://example.test/releases',
      keys: [k.raw],
      dir,
      fetch: async (url) => {
        fetched.push(url);
        if (url.endsWith('/latest/download/silo-update.json')) return new Response(JSON.stringify(manifest));
        if (url.endsWith(`/download/v${version}/${name}`)) return new Response(opts.served ?? installer);
        return new Response('nope', { status: 404 });
      },
      launch: (f) => launched.push(f),
      onChange: (v) => views.push(v),
    });
    return { u, dir, name, fetched, launched, views };
  }

  it('downloads a verified installer and runs it', async () => {
    const t = setup({});
    await t.u.check();
    expect(t.u.state.status).toBe('ready');
    expect(t.u.state.version).toBe('0.2.0');
    await t.u.install();
    expect(t.launched).toEqual([path.join(t.dir, t.name)]);
  });

  it('deletes a download whose hash does not match the signed one', async () => {
    const t = setup({ served: Buffer.from('malware') });
    await t.u.check();
    expect(t.u.state.status).toBe('error');
    expect(t.u.state.error).toMatch(/does not match/);
    expect(readdirSync(t.dir)).toEqual([]);
    await expect(t.u.install()).rejects.toThrow();
    expect(t.launched).toEqual([]);
  });

  it('refuses an installer changed on disk after download', async () => {
    const t = setup({});
    await t.u.check();
    writeFileSync(path.join(t.dir, t.name), 'swapped');
    await expect(t.u.install()).rejects.toThrow(/changed/);
    expect(t.launched).toEqual([]);
    expect(existsSync(path.join(t.dir, t.name))).toBe(false);
  });

  it('ignores a release that is not newer, so old signed releases cannot downgrade', async () => {
    const t = setup({ version: '0.1.0' });
    await t.u.check();
    expect(t.u.state.status).toBe('up-to-date');
    expect(t.fetched).toHaveLength(1);
  });

  it('only reports the update on platforms it cannot install on', async () => {
    const t = setup({ platform: 'linux' });
    await t.u.check();
    expect(t.u.state).toMatchObject({ status: 'available', canInstall: false, version: '0.2.0' });
    expect(t.fetched).toHaveLength(1);
  });

  it('is disabled without a key', async () => {
    const u = new Updater({
      currentVersion: '0.1.0',
      platform: 'win32',
      arch: 'x64',
      feed: 'x',
      keys: [],
      dir: tmpdir(),
      fetch: () => Promise.reject(new Error('should not fetch')),
      launch: () => undefined,
      onChange: () => undefined,
    });
    await u.check();
    expect(u.state.status).toBe('disabled');
  });
});
