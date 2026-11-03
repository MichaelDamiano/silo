import {
  ChallengeResponse,
  MeResponse,
  SessionResponse,
  loginPayload,
  sign,
  signupPayload,
  toBase64Url,
  type DeviceKeyPair,
} from '@silo/protocol';
import type { AccountView, SignupInput } from '../shared/ipc.js';

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
    headers: { 'content-type': 'application/json', ...init.headers },
    redirect: 'error',
  });
  const body = res.status === 204 ? undefined : await res.json().catch(() => undefined);
  if (!res.ok) {
    const message = (body as { error?: string } | undefined)?.error ?? `request failed (${res.status})`;
    throw new Error(message);
  }
  return parse(body);
}

export class SiloClient {
  private session?: { base: string; token: string };

  constructor(private readonly key: DeviceKeyPair) {}

  get publicKey() {
    return toBase64Url(this.key.publicKey);
  }

  private challenge(base: string) {
    return call(base, '/v1/auth/challenge', { method: 'POST', body: JSON.stringify({ devicePublicKey: this.publicKey }) }, (v) =>
      ChallengeResponse.parse(v),
    );
  }

  async signup(input: SignupInput): Promise<AccountView> {
    const base = normalizeServerUrl(input.serverUrl);
    const c = await this.challenge(base);
    const session = await call(
      base,
      '/v1/accounts',
      {
        method: 'POST',
        body: JSON.stringify({
          inviteCode: input.inviteCode.trim(),
          username: input.username.trim(),
          deviceName: input.deviceName.trim(),
          devicePublicKey: this.publicKey,
          challengeId: c.challengeId,
          signature: sign(signupPayload(c.nonce, input.username.trim()), this.key.secretKey),
        }),
      },
      (v) => SessionResponse.parse(v),
    );
    this.session = { base, token: session.token };
    return this.me();
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
    this.session = { base, token: session.token };
    return this.me();
  }

  async logout(): Promise<void> {
    const s = this.session;
    this.session = undefined;
    if (s) await call(s.base, '/v1/auth/logout', { method: 'POST', headers: { authorization: `Bearer ${s.token}` } }, () => undefined);
  }

  async me(): Promise<AccountView> {
    const s = this.session;
    if (!s) throw new Error('Not signed in.');
    const me = await call(s.base, '/v1/me', { headers: { authorization: `Bearer ${s.token}` } }, (v) => MeResponse.parse(v));
    return {
      username: me.username,
      devices: me.devices.map((d) => ({ id: d.id, name: d.name, current: d.current, revoked: d.revokedAt !== null, createdAt: d.createdAt })),
    };
  }
}
