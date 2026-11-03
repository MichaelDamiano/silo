import {
  ChallengeResponse,
  CreateInviteResponse,
  LinkRequestResponse,
  MeResponse,
  PendingLink,
  SessionResponse,
  fingerprint,
  formatRecoveryKey,
  generateDeviceKeyPair,
  linkApprovePayload,
  linkRequestPayload,
  loginPayload,
  parseRecoveryKey,
  publicKeyFromSecret,
  recoverPayload,
  rotateRecoveryPayload,
  sign,
  signupPayload,
  toBase64Url,
  type DeviceKeyPair,
} from '@silo/protocol';
import { z } from 'zod';
import type { AccountView, LinkTicket, PendingDevice, RecoverInput, SignupInput } from '../shared/ipc.js';
import { runSpaceAction } from './spaces.js';

/** Plain http is only allowed to this machine, for local development. */
export function normalizeServerUrl(input: string): string {
  const url = new URL(input.trim());
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error('The server address must use https:// (http:// is only allowed for localhost).');
  }
  if (url.username || url.password) throw new Error('The server address must not contain a username or password.');
  return url.origin;
}

async function call<T>(base: string, path: string, init: RequestInit, parse: (v: unknown) => T): Promise<T> {
  const res = await fetch(base + path, {
    ...init,
    headers: { ...(init.body === undefined ? {} : { 'content-type': 'application/json' }), ...init.headers },
    redirect: 'error',
  });
  const body = res.status === 204 ? undefined : await res.json().catch(() => undefined);
  if (!res.ok) {
    const message = (body as { error?: string } | undefined)?.error ?? `request failed (${res.status})`;
    throw new Error(message);
  }
  return parse(body);
}

const none = () => undefined;

export class SiloClient {
  private session?: { base: string; token: string; userId: string };
  private waitingLink?: { base: string };
  private lookedUp?: PendingLink;

  constructor(private readonly key: DeviceKeyPair) {}

  get publicKey() {
    return toBase64Url(this.key.publicKey);
  }

  get fingerprint() {
    return fingerprint(this.publicKey);
  }

  private challenge(base: string) {
    return call(base, '/v1/auth/challenge', { method: 'POST', body: JSON.stringify({ devicePublicKey: this.publicKey }) }, (v) =>
      ChallengeResponse.parse(v),
    );
  }

  private authed<T>(path: string, init: RequestInit, parse: (v: unknown) => T): Promise<T> {
    const s = this.session;
    if (!s) throw new Error('Not signed in.');
    return call(s.base, path, { ...init, headers: { ...init.headers, authorization: `Bearer ${s.token}` } }, parse);
  }

  private post<T>(path: string, body: unknown, parse: (v: unknown) => T = none as () => T): Promise<T> {
    return this.authed(path, { method: 'POST', body: JSON.stringify(body) }, parse);
  }

  async signup(input: SignupInput): Promise<{ account: AccountView; recoveryKey: string }> {
    const base = normalizeServerUrl(input.serverUrl);
    const username = input.username.trim();
    // The recovery key is never stored: it is shown once for the user to write down.
    const recovery = generateDeviceKeyPair();
    const recoveryPublicKey = toBase64Url(recovery.publicKey);
    const c = await this.challenge(base);
    const session = await call(
      base,
      '/v1/accounts',
      {
        method: 'POST',
        body: JSON.stringify({
          inviteCode: input.inviteCode.trim(),
          username,
          deviceName: input.deviceName.trim(),
          devicePublicKey: this.publicKey,
          recoveryPublicKey,
          challengeId: c.challengeId,
          signature: sign(signupPayload(c.nonce, username, recoveryPublicKey), this.key.secretKey),
        }),
      },
      (v) => SessionResponse.parse(v),
    );
    this.session = { base, token: session.token, userId: session.userId };
    return { account: await this.me(), recoveryKey: formatRecoveryKey(recovery.secretKey) };
  }

  async login(serverUrl: string): Promise<AccountView> {
    const base = normalizeServerUrl(serverUrl);
    const c = await this.challenge(base);
    const session = await call(
      base,
      '/v1/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({
          devicePublicKey: this.publicKey,
          challengeId: c.challengeId,
          signature: sign(loginPayload(c.nonce), this.key.secretKey),
        }),
      },
      (v) => SessionResponse.parse(v),
    );
    this.session = { base, token: session.token, userId: session.userId };
    return this.me();
  }

  async logout(): Promise<void> {
    if (this.session) await this.post('/v1/auth/logout', {}).catch(none);
    this.session = undefined;
    this.lookedUp = undefined;
  }

  async requestLink(input: { serverUrl: string; username: string; deviceName: string }): Promise<LinkTicket> {
    const base = normalizeServerUrl(input.serverUrl);
    const username = input.username.trim();
    const deviceName = input.deviceName.trim();
    const c = await this.challenge(base);
    const res = await call(
      base,
      '/v1/device-links',
      {
        method: 'POST',
        body: JSON.stringify({
          username,
          deviceName,
          devicePublicKey: this.publicKey,
          challengeId: c.challengeId,
          signature: sign(linkRequestPayload(c.nonce, username, deviceName), this.key.secretKey),
        }),
      },
      (v) => LinkRequestResponse.parse(v),
    );
    this.waitingLink = { base };
    const code = res.pairingCode;
    return { pairingCode: `${code.slice(0, 5)}-${code.slice(5)}`, fingerprint: this.fingerprint, expiresAt: res.expiresAt };
  }

  async checkLink(): Promise<AccountView | null> {
    const waiting = this.waitingLink;
    if (!waiting) throw new Error('This device is not waiting for approval.');
    const { approved } = await call(
      waiting.base,
      '/v1/device-links/status',
      { method: 'POST', body: JSON.stringify({ devicePublicKey: this.publicKey }) },
      (v) => z.object({ approved: z.boolean() }).parse(v),
    );
    if (!approved) return null;
    this.waitingLink = undefined;
    return this.login(waiting.base);
  }

  async lookupLink(pairingCode: string): Promise<PendingDevice> {
    const link = await this.post('/v1/device-links/lookup', { pairingCode }, (v) => PendingLink.parse(v));
    this.lookedUp = link;
    return { deviceName: link.deviceName, fingerprint: link.fingerprint, expiresAt: link.expiresAt };
  }

  /** Signs the key the server returned at lookup, so the renderer can't swap in a different one. */
  async approveLink(): Promise<AccountView> {
    const link = this.lookedUp;
    if (!link) throw new Error('Look up a pairing code first.');
    await this.post('/v1/device-links/approve', {
      linkId: link.linkId,
      signature: sign(linkApprovePayload(link.linkId, link.devicePublicKey), this.key.secretKey),
    });
    this.lookedUp = undefined;
    return this.me();
  }

  async revokeDevice(deviceId: string): Promise<AccountView> {
    await this.post(`/v1/devices/${encodeURIComponent(deviceId)}/revoke`, {});
    const me = await this.me().catch(() => undefined);
    if (!me) {
      // We revoked this very device, so its session is gone too.
      this.session = undefined;
      throw new Error('This device was revoked and signed out.');
    }
    return me;
  }

  async recover(input: RecoverInput): Promise<{ account: AccountView; recoveryKey: string }> {
    const base = normalizeServerUrl(input.serverUrl);
    const username = input.username.trim();
    const recoverySecret = parseRecoveryKey(input.recoveryKey);
    const c = await this.challenge(base);
    const payload = recoverPayload(c.nonce, username, this.publicKey);
    const session = await call(
      base,
      '/v1/accounts/recover',
      {
        method: 'POST',
        body: JSON.stringify({
          username,
          deviceName: input.deviceName.trim(),
          devicePublicKey: this.publicKey,
          recoveryPublicKey: toBase64Url(publicKeyFromSecret(recoverySecret)),
          challengeId: c.challengeId,
          deviceSignature: sign(payload, this.key.secretKey),
          recoverySignature: sign(payload, recoverySecret),
        }),
      },
      (v) => SessionResponse.parse(v),
    );
    this.session = { base, token: session.token, userId: session.userId };
    // The old recovery key has now been typed in, so replace it straight away.
    const { recoveryKey } = await this.rotateRecoveryKey();
    return { account: await this.me(), recoveryKey };
  }

  async rotateRecoveryKey(): Promise<{ recoveryKey: string }> {
    const s = this.session;
    if (!s) throw new Error('Not signed in.');
    const next = generateDeviceKeyPair();
    const recoveryPublicKey = toBase64Url(next.publicKey);
    await this.post('/v1/recovery-key', {
      recoveryPublicKey,
      signature: sign(rotateRecoveryPayload(s.userId, recoveryPublicKey), next.secretKey),
    });
    return { recoveryKey: formatRecoveryKey(next.secretKey) };
  }

  createAccountInvite() {
    return this.post('/v1/invites', { maxUses: 1, expiresInHours: 72 }, (v) => CreateInviteResponse.parse(v));
  }

  space(action: unknown): Promise<unknown> {
    return runSpaceAction(action, (method, path, body, parse) =>
      this.authed(path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, parse),
    );
  }

  async me(): Promise<AccountView> {
    const me = await this.authed('/v1/me', {}, (v) => MeResponse.parse(v));
    return {
      username: me.username,
      devices: me.devices.map((d) => ({
        id: d.id,
        name: d.name,
        current: d.current,
        revoked: d.revokedAt !== null,
        createdAt: d.createdAt,
        fingerprint: fingerprint(d.publicKey),
      })),
    };
  }
}
