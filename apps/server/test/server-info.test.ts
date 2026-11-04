import { describe, expect, it } from 'vitest';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { ServerInfo, serverInfoPayload, verify } from '@silo/protocol';
import { buildApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { app, databaseUrl, db } from './helpers/setup.js';

const nonce = 'n0nce-n0nce-n0nce-1234';

describe('server info', () => {
  it('signs its address list and the client nonce with a stable identity key', async () => {
    const res = await app.inject({ method: 'GET', url: `/v1/server-info?nonce=${nonce}` });
    expect(res.statusCode).toBe(200);
    const { info, signature } = res.json();
    const parsed = ServerInfo.parse(JSON.parse(info));
    expect(parsed.nonce).toBe(nonce);
    expect(verify(signature, serverInfoPayload(info), parsed.serverKey)).toBe(true);
    // Tampering with the list breaks the signature.
    const forged = JSON.stringify({ ...parsed, endpoints: ['https://evil.example'] });
    expect(verify(signature, serverInfoPayload(forged), parsed.serverKey)).toBe(false);

    const again = ServerInfo.parse(JSON.parse((await app.inject({ method: 'GET', url: `/v1/server-info?nonce=${nonce}x` })).json().info));
    expect(again.serverKey).toBe(parsed.serverKey);
  });

  it('requires a nonce', async () => {
    expect((await app.inject({ method: 'GET', url: '/v1/server-info' })).statusCode).toBe(400);
  });

  it('publishes configured addresses and the onion address Tor created', async () => {
    const dir = await mkdtemp(path.join(tmpdir(), 'silo-onion-'));
    const onion = `${'a'.repeat(56)}.onion`;
    await writeFile(path.join(dir, 'hostname'), `${onion}\n`);
    const other = await buildApp(
      loadConfig({
        DATABASE_URL: databaseUrl,
        PUBLIC_URLS: 'https://silo.example.com, https://mirror.example.net:8443/',
        ONION_HOSTNAME_FILE: path.join(dir, 'hostname'),
      }),
      db,
      { logger: false },
    );
    const info = ServerInfo.parse(JSON.parse((await other.inject({ method: 'GET', url: `/v1/server-info?nonce=${nonce}` })).json().info));
    expect(info.endpoints).toEqual(['https://silo.example.com', 'https://mirror.example.net:8443', `http://${onion}`]);
    await other.close();
  });

  it('refuses plain http addresses other than onion and localhost', () => {
    expect(() => loadConfig({ DATABASE_URL: databaseUrl, PUBLIC_URLS: 'http://silo.example.com' })).toThrow(/PUBLIC_URLS/);
  });
});
