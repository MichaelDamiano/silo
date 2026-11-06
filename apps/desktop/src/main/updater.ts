import { createHash, createPublicKey, verify } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, readdir, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import type { UpdateView } from '../shared/ipc.js';

/**
 * Updates are trusted only through a signature, never through where they came from.
 *
 * A release carries `silo-update.json`: a payload listing the version and the SHA-256
 * of every file, signed with a release key that stays offline with the maintainer.
 * The app checks the signature against keys built into it, refuses anything not newer
 * than itself, and checks the installer's hash before running it. Someone who takes
 * over the GitHub account, the build machine or the download path still can't ship
 * an update without the key.
 */

export const MANIFEST_NAME = 'silo-update.json';
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_FILE_BYTES = 512 * 1024 * 1024;

const Envelope = z.object({
  payload: z.string().max(MAX_MANIFEST_BYTES).regex(/^[A-Za-z0-9+/]+=*$/),
  signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/),
});

const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}$/;

const Payload = z.object({
  app: z.literal('silo-desktop'),
  version: z.string().regex(VERSION),
  released: z.string().max(64),
  notes: z.string().max(4000).optional(),
  files: z
    .array(z.object({ name: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/), sha256: z.string().regex(/^[0-9a-f]{64}$/) }))
    .min(1)
    .max(100),
});

export type UpdateManifest = z.infer<typeof Payload>;

// DER prefix that turns a raw 32-byte Ed25519 key into an SPKI public key.
const ED25519_SPKI = Buffer.from('302a300506032b6570032100', 'hex');

function publicKey(raw: string) {
  const bytes = Buffer.from(raw, 'base64');
  if (bytes.length !== 32) throw new Error('bad update key');
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI, bytes]), format: 'der', type: 'spki' });
}

/** Parses a downloaded manifest and returns its contents only if one of `keys` signed it. */
export function verifyManifest(raw: unknown, keys: readonly string[]): UpdateManifest {
  if (keys.length === 0) throw new Error('This build has no update key, so it cannot check updates.');
  const env = Envelope.parse(raw);
  const payload = Buffer.from(env.payload, 'base64');
  const signature = Buffer.from(env.signature, 'base64');
  if (!keys.some((k) => verify(null, payload, publicKey(k), signature))) throw new Error('The update is not signed by a Silo release key.');
  return Payload.parse(JSON.parse(payload.toString('utf8')));
}

/** True when version `a` is newer than `b` (plain x.y.z). */
export function isNewer(a: string, b: string): boolean {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) > (pb[i] ?? 0);
  return false;
}

/** The file this device can install by itself, if any. Only the Windows installer for now. */
export function installerFor(m: UpdateManifest, platform: string, arch: string) {
  if (platform !== 'win32') return undefined;
  return m.files.find((f) => f.name === `silo-${m.version}-win-${arch}.exe`);
}

async function sha256File(file: string): Promise<string> {
  const h = createHash('sha256');
  for await (const chunk of createReadStream(file)) h.update(chunk as Buffer);
  return h.digest('hex');
}

export interface UpdaterOptions {
  currentVersion: string;
  platform: string;
  arch: string;
  feed: string;
  keys: readonly string[];
  /** Folder that holds downloaded installers. */
  dir: string;
  /** Does the network request, through Tor when the user asked for that. */
  fetch: (url: string, init: { signal: AbortSignal }) => Promise<Response>;
  /** Starts the verified installer and quits. */
  launch: (installer: string) => void;
  onChange: (view: UpdateView) => void;
}

export class Updater {
  private view: UpdateView;
  private manifest?: UpdateManifest;
  private ready?: { file: string; sha256: string };
  private running?: Promise<void>;

  constructor(private readonly o: UpdaterOptions) {
    this.view = { status: o.keys.length ? 'idle' : 'disabled', current: o.currentVersion, canInstall: false };
  }

  get state(): UpdateView {
    return this.view;
  }

  private set(patch: Partial<UpdateView>) {
    this.view = { ...this.view, ...patch };
    this.o.onChange(this.view);
  }

  /** Looks for a newer signed release and, on Windows, downloads and checks it. */
  check(): Promise<void> {
    if (this.view.status === 'disabled') return Promise.resolve();
    return (this.running ??= this.run().finally(() => (this.running = undefined)));
  }

  private async run() {
    if (this.ready) return;
    this.set({ status: 'checking', error: undefined });
    try {
      const m = await this.fetchManifest();
      if (!isNewer(m.version, this.o.currentVersion)) {
        this.set({ status: 'up-to-date', checkedAt: new Date().toISOString() });
        return;
      }
      this.manifest = m;
      const file = installerFor(m, this.o.platform, this.o.arch);
      this.set({ status: 'available', version: m.version, notes: m.notes, canInstall: !!file, checkedAt: new Date().toISOString() });
      if (!file) return;
      this.set({ status: 'downloading', progress: 0 });
      this.ready = { file: await this.download(m.version, file.name, file.sha256), sha256: file.sha256 };
      this.set({ status: 'ready', progress: undefined });
    } catch (err) {
      this.set({ status: 'error', progress: undefined, error: err instanceof Error ? err.message : String(err) });
    }
  }

  private async fetchManifest(): Promise<UpdateManifest> {
    const res = await this.o.fetch(`${this.o.feed}/latest/download/${MANIFEST_NAME}`, { signal: AbortSignal.timeout(60_000) });
    if (res.status === 404) throw new Error('No signed release has been published yet.');
    if (!res.ok) throw new Error(`Update check failed (${res.status}).`);
    const text = await res.text();
    if (text.length > MAX_MANIFEST_BYTES) throw new Error('The update manifest is too large.');
    return verifyManifest(JSON.parse(text), this.o.keys);
  }

  /** Streams the file to disk while hashing it, and keeps it only if the hash matches the signed one. */
  private async download(version: string, name: string, sha256: string): Promise<string> {
    await mkdir(this.o.dir, { recursive: true });
    // Old installers are of no use once a newer one is picked.
    for (const old of await readdir(this.o.dir)) if (old !== name) await rm(path.join(this.o.dir, old), { force: true, recursive: true });
    const final = path.join(this.o.dir, name);
    const partial = `${final}.partial`;
    const res = await this.o.fetch(`${this.o.feed}/download/v${version}/${name}`, { signal: AbortSignal.timeout(30 * 60_000) });
    if (!res.ok || !res.body) throw new Error(`Download failed (${res.status}).`);
    const total = Number(res.headers.get('content-length')) || 0;
    const hash = createHash('sha256');
    const out = createWriteStream(partial);
    let got = 0;
    try {
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        got += chunk.length;
        if (got > MAX_FILE_BYTES) throw new Error('The download is larger than any Silo release.');
        hash.update(chunk);
        if (!out.write(chunk)) await new Promise<void>((r) => out.once('drain', () => r()));
        if (total) this.set({ progress: Math.min(1, got / total) });
      }
      await new Promise<void>((resolve, reject) => out.end((err?: Error | null) => (err ? reject(err) : resolve())));
    } catch (err) {
      out.destroy();
      await rm(partial, { force: true });
      throw err;
    }
    if (hash.digest('hex') !== sha256) {
      await rm(partial, { force: true });
      throw new Error('The download does not match the signed release, so it was deleted.');
    }
    await rename(partial, final);
    return final;
  }

  /** Runs the downloaded installer after checking its hash once more. */
  async install(): Promise<void> {
    if (!this.ready) throw new Error('No update is ready to install.');
    if ((await sha256File(this.ready.file)) !== this.ready.sha256) {
      await rm(this.ready.file, { force: true });
      this.ready = undefined;
      this.set({ status: 'error', error: 'The downloaded update changed on disk, so it was deleted.' });
      throw new Error('The downloaded update changed on disk.');
    }
    this.o.launch(this.ready.file);
  }
}
