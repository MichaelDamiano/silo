import { afterAll, beforeAll, beforeEach, expect } from 'vitest';
import type { FastifyInstance } from 'fastify';
import {
  generateDeviceKeyPair,
  loginPayload,
  sign,
  signupPayload,
  toBase64Url,
  type DeviceKeyPair,
} from '@silo/protocol';
import { buildApp } from '../../src/app.js';
import { loadConfig } from '../../src/config.js';
import { createPool, migrate, type Db } from '../../src/db.js';
import { createInvite } from '../../src/invites.js';

export const databaseUrl = process.env.TEST_DATABASE_URL ?? 'postgres://silo:silo@localhost:5432/silo_test';
export let db: Db;
export let app: FastifyInstance;

beforeAll(async () => {
  db = createPool(databaseUrl);
  await migrate(db);
  app = await buildApp(loadConfig({ DATABASE_URL: databaseUrl, AUTH_RATE_LIMIT_PER_MINUTE: '1000' }), db, { logger: false });
});

afterAll(async () => {
  await app.close();
  await db.end();
});

beforeEach(async () => {
  await db.query('TRUNCATE users, devices, invites, challenges, sessions, device_links CASCADE');
});

export const pub = (kp: DeviceKeyPair) => toBase64Url(kp.publicKey);

export async function challenge(kp: DeviceKeyPair) {
  const res = await app.inject({ method: 'POST', url: '/v1/auth/challenge', payload: { devicePublicKey: pub(kp) } });
  expect(res.statusCode).toBe(200);
  return res.json() as { challengeId: string; nonce: string };
}

export async function signup(kp: DeviceKeyPair, username: string, inviteCode: string, recovery = generateDeviceKeyPair()) {
  const c = await challenge(kp);
  return app.inject({
    method: 'POST',
    url: '/v1/accounts',
    payload: {
      inviteCode,
      username,
      deviceName: 'Laptop',
      devicePublicKey: pub(kp),
      recoveryPublicKey: pub(recovery),
      challengeId: c.challengeId,
      signature: sign(signupPayload(c.nonce, username, pub(recovery)), kp.secretKey),
    },
  });
}

export async function login(kp: DeviceKeyPair) {
  const c = await challenge(kp);
  return app.inject({
    method: 'POST',
    url: '/v1/auth/login',
    payload: { devicePublicKey: pub(kp), challengeId: c.challengeId, signature: sign(loginPayload(c.nonce), kp.secretKey) },
  });
}

export const invite = (maxUses = 1) => createInvite(db, { createdBy: null, maxUses, expiresInHours: 1 }).then((i) => i.code);
export const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

