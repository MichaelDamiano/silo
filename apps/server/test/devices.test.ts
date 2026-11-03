import { describe, expect, it } from 'vitest';
import {
  fingerprint,
  generateDeviceKeyPair,
  linkApprovePayload,
  linkRequestPayload,
  recoverPayload,
  rotateRecoveryPayload,
  sign,
  type DeviceKeyPair,
} from '@silo/protocol';
import { app, bearer, challenge, db, invite, login, pub, signup } from './helpers/setup.js';

async function requestLink(kp: DeviceKeyPair, username: string, deviceName = 'Desktop') {
  const c = await challenge(kp);
  return app.inject({
    method: 'POST',
    url: '/v1/device-links',
    payload: {
      username,
      deviceName,
      devicePublicKey: pub(kp),
      challengeId: c.challengeId,
      signature: sign(linkRequestPayload(c.nonce, username, deviceName), kp.secretKey),
    },
  });
}

async function lookup(token: string, pairingCode: string) {
  return app.inject({ method: 'POST', url: '/v1/device-links/lookup', headers: bearer(token), payload: { pairingCode } });
}

async function approve(token: string, approver: DeviceKeyPair, linkId: string, newKey: string) {
  return app.inject({
    method: 'POST',
    url: '/v1/device-links/approve',
    headers: bearer(token),
    payload: { linkId, signature: sign(linkApprovePayload(linkId, newKey), approver.secretKey) },
  });
}

async function recover(username: string, recovery: DeviceKeyPair, device: DeviceKeyPair, signWith = recovery) {
  const c = await challenge(device);
  const payload = recoverPayload(c.nonce, username, pub(device));
  return app.inject({
    method: 'POST',
    url: '/v1/accounts/recover',
    payload: {
      username,
      deviceName: 'Recovered laptop',
      devicePublicKey: pub(device),
      recoveryPublicKey: pub(recovery),
      challengeId: c.challengeId,
      deviceSignature: sign(payload, device.secretKey),
      recoverySignature: sign(payload, signWith.secretKey),
    },
  });
}

const status = (kp: DeviceKeyPair) =>
  app.inject({ method: 'POST', url: '/v1/device-links/status', payload: { devicePublicKey: pub(kp) } }).then((r) => r.json().approved);

describe('linking a new device', () => {
  it('adds the device once an existing device approves it', async () => {
    const first = generateDeviceKeyPair();
    const { token, deviceId } = (await signup(first, 'mike', await invite())).json();
    const second = generateDeviceKeyPair();

    const link = await requestLink(second, 'mike', 'Desktop');
    expect(link.statusCode).toBe(201);
    expect(await status(second)).toBe(false);
    expect((await login(second)).statusCode).toBe(401);

    // Pairing codes are accepted with spaces, dashes and lowercase.
    const code: string = link.json().pairingCode;
    const typed = `${code.slice(0, 5)}-${code.slice(5)}`.toLowerCase();
    const found = await lookup(token, typed);
    expect(found.statusCode).toBe(200);
    expect(found.json()).toMatchObject({ deviceName: 'Desktop', devicePublicKey: pub(second), fingerprint: fingerprint(pub(second)) });

    expect((await approve(token, first, found.json().linkId, pub(second))).statusCode).toBe(204);
    expect(await status(second)).toBe(true);
    const session = await login(second);
    expect(session.statusCode).toBe(200);

    const me = await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(session.json().token) });
    expect(me.json().devices).toHaveLength(2);
    expect(me.json().devices[1]).toMatchObject({ name: 'Desktop', approvedBy: deviceId, current: true });
  });

  it('gives the same answer for a username that does not exist', async () => {
    const res = await requestLink(generateDeviceKeyPair(), 'nobody');
    expect(res.statusCode).toBe(201);
    expect(res.json().pairingCode).toMatch(/^[A-Z2-7]{10}$/);
  });

  it("does not show one user's pending device to another user", async () => {
    const code = await invite(2);
    await signup(generateDeviceKeyPair(), 'mike', code);
    const other = (await signup(generateDeviceKeyPair(), 'eve', code)).json();
    const link = (await requestLink(generateDeviceKeyPair(), 'mike')).json();
    expect((await lookup(other.token, link.pairingCode)).statusCode).toBe(404);
  });

  it('rejects an approval signature from the wrong key', async () => {
    const first = generateDeviceKeyPair();
    const { token } = (await signup(first, 'mike', await invite())).json();
    const second = generateDeviceKeyPair();
    const link = (await requestLink(second, 'mike')).json();
    const { linkId } = (await lookup(token, link.pairingCode)).json();
    expect((await approve(token, generateDeviceKeyPair(), linkId, pub(second))).statusCode).toBe(401);
    expect(await status(second)).toBe(false);
  });

  it('does not approve the same link twice or after it expires', async () => {
    const first = generateDeviceKeyPair();
    const { token } = (await signup(first, 'mike', await invite())).json();
    const second = generateDeviceKeyPair();
    const { linkId } = (await lookup(token, (await requestLink(second, 'mike')).json().pairingCode)).json();
    expect((await approve(token, first, linkId, pub(second))).statusCode).toBe(204);
    expect((await approve(token, first, linkId, pub(second))).statusCode).toBe(404);

    const third = generateDeviceKeyPair();
    const pending = (await lookup(token, (await requestLink(third, 'mike')).json().pairingCode)).json();
    await db.query(`UPDATE device_links SET expires_at = now() - interval '1 second' WHERE id = $1`, [pending.linkId]);
    expect((await approve(token, first, pending.linkId, pub(third))).statusCode).toBe(404);
  });

  it('caps how many devices can wait for approval at once', async () => {
    await signup(generateDeviceKeyPair(), 'mike', await invite());
    const codes: number[] = [];
    for (let i = 0; i < 6; i++) codes.push((await requestLink(generateDeviceKeyPair(), 'mike')).statusCode);
    expect(codes).toEqual([201, 201, 201, 201, 201, 429]);
  });
});

describe('recovery key', () => {
  it('regains access and revokes every old device', async () => {
    const recovery = generateDeviceKeyPair();
    const lost = generateDeviceKeyPair();
    const old = (await signup(lost, 'mike', await invite(), recovery)).json();
    const fresh = generateDeviceKeyPair();

    const res = await recover('mike', recovery, fresh);
    expect(res.statusCode).toBe(201);
    expect((await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(old.token) })).statusCode).toBe(401);
    expect((await login(lost)).statusCode).toBe(401);

    const me = (await app.inject({ method: 'GET', url: '/v1/me', headers: bearer(res.json().token) })).json();
    expect(me.devices.filter((d: { revokedAt: string | null }) => d.revokedAt === null)).toHaveLength(1);
  });

  it('rejects the wrong recovery key or a forged signature', async () => {
    const recovery = generateDeviceKeyPair();
    await signup(generateDeviceKeyPair(), 'mike', await invite(), recovery);
    expect((await recover('mike', generateDeviceKeyPair(), generateDeviceKeyPair())).statusCode).toBe(401);
    expect((await recover('mike', recovery, generateDeviceKeyPair(), generateDeviceKeyPair())).statusCode).toBe(401);
    expect((await recover('someone_else', recovery, generateDeviceKeyPair())).statusCode).toBe(401);
  });

  it('can be replaced, after which the old one stops working', async () => {
    const recovery = generateDeviceKeyPair();
    const { token, userId } = (await signup(generateDeviceKeyPair(), 'mike', await invite(), recovery)).json();
    const next = generateDeviceKeyPair();
    const rotate = await app.inject({
      method: 'POST',
      url: '/v1/recovery-key',
      headers: bearer(token),
      payload: { recoveryPublicKey: pub(next), signature: sign(rotateRecoveryPayload(userId, pub(next)), next.secretKey) },
    });
    expect(rotate.statusCode).toBe(204);
    expect((await recover('mike', recovery, generateDeviceKeyPair())).statusCode).toBe(401);
    expect((await recover('mike', next, generateDeviceKeyPair())).statusCode).toBe(201);
  });

  it('will not set a recovery key the client cannot prove it holds', async () => {
    const { token, userId } = (await signup(generateDeviceKeyPair(), 'mike', await invite())).json();
    const next = generateDeviceKeyPair();
    const res = await app.inject({
      method: 'POST',
      url: '/v1/recovery-key',
      headers: bearer(token),
      payload: { recoveryPublicKey: pub(next), signature: sign(rotateRecoveryPayload(userId, pub(next)), generateDeviceKeyPair().secretKey) },
    });
    expect(res.statusCode).toBe(401);
  });
});
