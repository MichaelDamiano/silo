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
import { HttpStatusError, Messenger } from './messenger.js';
import { Safety } from './safety.js';
import type { Vault } from './vault.js';
import { ServerDirectory, type KnownServer } from './servers.js';
import { UnreachableError, type Transport } from './transport.js';
import type { AppEvent, ChannelView, ConnectionView, Conversation, ConversationSummary } from '../shared/ipc.js';

const DmActionSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('list') }),
  z.object({ kind: z.literal('get'), peerUserId: z.uuid(), peerUsername: z.string().max(32).optional() }),
  z.object({ kind: z.literal('send'), peerUserId: z.uuid(), peerUsername: z.string().max(32), text: z.string().max(4000) }),
]);

const ConnectionActionSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('get') }),
  z.object({
    kind: z.literal('setTor'),
    proxyHost: z.string().regex(/^[A-Za-z0-9.:[\]-]{1,255}$/),
    proxyPort: z.number().int().min(1).max(65535),
    always: z.boolean(),
  }),
  z.object({ kind: z.literal('setLan'), enabled: z.boolean() }),
  z.object({ kind: z.literal('addAddress'), address: z.string().max(256) }),
  z.object({ kind: z.literal('removeAddress'), address: z.string().max(256) }),
]);

const ChannelActionSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('get'), spaceId: z.uuid(), channelId: z.uuid() }),
  z.object({ kind: z.literal('send'), spaceId: z.uuid(), channelId: z.uuid(), text: z.string().max(4000) }),
]);

export { normalizeServerUrl } from './servers.js';

type Init = { method?: string; headers?: Record<string, string>; body?: string };

async function call<T>(net: Transport, path: string, init: Init, parse: (v: unknown) => T): Promise<T> {
  const res = await net.request(path, {
    ...init,
    headers: { ...(init.body === undefined ? {} : { 'content-type': 'application/json' }), ...init.headers },
  });
  const body = res.status === 204 ? undefined : await res.json().catch(() => undefined);
  if (!res.ok) {
    const message = (body as { error?: string } | undefined)?.error ?? `request failed (${res.status})`;
    throw new HttpStatusError(res.status, body, message);
  }
  return parse(body);
}

const none = () => undefined;

export class SiloClient {
  private session?: { net: Transport; server: KnownServer; token: string; userId: string; deviceId: string };
  private waitingLink?: { net: Transport; server: KnownServer };
  private dir?: Promise<ServerDirectory>;
  private readonly spaceCache = new Map<string, unknown>();
  private lookedUp?: PendingLink;
  private checking?: Promise<AccountView | null>;
  private messenger?: Messenger;
  private safetyCenter?: Safety;

  constructor(
    private readonly key: DeviceKeyPair,
    private readonly vault?: Vault,
    private readonly emit: (event: AppEvent) => void = () => undefined,
  ) {}

  private directory(): Promise<ServerDirectory> {
    return (this.dir ??= ServerDirectory.open(this.vault));
  }

  /** Finds a working address for the server and checks its identity before anything is sent. */
  private async connect(serverUrl: string) {
    return (await this.directory()).connect(serverUrl, (endpoint, viaTor) => this.emit({ type: 'connection', endpoint, viaTor }));
  }

  private signedIn(net: Transport, server: KnownServer, s: { token: string; userId: string; deviceId: string }) {
    if (this.session && this.session.net !== net) this.session.net.close();
    this.session = { net, server, token: s.token, userId: s.userId, deviceId: s.deviceId };
    this.emit({ type: 'connection', endpoint: net.current, viaTor: net.viaTor() });
  }

  private endSession() {
    this.spaceCache.clear();
    this.messenger?.stop();
    this.messenger = undefined;
    this.safetyCenter = undefined;
    this.session?.net.close();
    this.session = undefined;
  }

  /** Starts encrypted messaging once signed in. Failures are reported but don't block sign-in. */
  private async startMessenger() {
    const s = this.session;
    if (!s || !this.vault) return;
    // Pick up any addresses the server has published since we last looked.
    await this.directory()
      .then((d) => d.refresh(s.net, s.server.serverKey))
      .then((server) => (s.server = server))
      .catch(() => undefined);
    this.messenger?.stop();
    try {
      this.messenger = await Messenger.start(
        this.vault,
        {
          token: s.token,
          userId: s.userId,
          deviceId: s.deviceId,
          socket: (path) => s.net.socket(path),
          request: (method, path, body, parse) =>
            this.authed(path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, parse),
          sign: (payload) => sign(payload, this.key.secretKey),
        },
        this.emit,
      );
      // Blocks are loaded before the local network starts, so nothing from a blocked person slips in.
      this.safetyCenter = await Safety.open(
        s.userId,
        this.vault,
        (method, path, body, parse) => this.authed(path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, parse),
        () => this.messenger,
      );
      if ((await this.directory()).lan) await this.messenger.setLan(true);
    } catch (err) {
      this.emit({ type: 'error', message: `Encrypted messaging couldn't start: ${(err as Error).message}` });
    }
  }

  async dm(input: unknown): Promise<ConversationSummary[] | Conversation> {
    const a = DmActionSchema.parse(input);
    const m = this.messenger;
    if (!m) throw new Error('Encrypted messaging isn’t running on this device.');
    if (a.kind === 'list') return m.conversations();
    if (a.kind === 'get') return m.conversation(a.peerUserId, a.peerUsername);
    return m.send(a.peerUserId, a.peerUsername, a.text);
  }

  async safety(input: unknown): Promise<unknown> {
    if (!this.safetyCenter) throw new Error('Sign in first.');
    return this.safetyCenter.run(input);
  }

  /** Connection settings: which address is in use, the server's addresses, and Tor. */
  async connection(input: unknown): Promise<ConnectionView> {
    const a = ConnectionActionSchema.parse(input);
    const dir = await this.directory();
    const s = this.session;
    if (a.kind === 'setTor') {
      const tor = { proxyHost: a.proxyHost, proxyPort: a.proxyPort, always: a.always };
      await dir.setTor(tor);
      s?.net.setTor(tor);
      this.waitingLink?.net.setTor(tor);
    } else if (a.kind === 'setLan') {
      await dir.setLan(a.enabled);
      await this.messenger?.setLan(a.enabled);
    } else if (a.kind === 'addAddress' || a.kind === 'removeAddress') {
      if (!s) throw new Error('Sign in first.');
      s.server =
        a.kind === 'addAddress' ? await dir.addAddress(s.server.serverKey, a.address) : await dir.removeAddress(s.server.serverKey, a.address);
      s.net.setEndpoints(dir.addressesFor(s.server, s.net.current));
    }
    return {
      tor: dir.tor,
      current: s ? { endpoint: s.net.current, viaTor: s.net.viaTor() } : null,
      serverFingerprint: s ? fingerprint(s.server.serverKey) : null,
      addresses: s
        ? dir.addressesFor(s.server).map((endpoint) => ({
            endpoint,
            published: s.server.endpoints.includes(endpoint),
            onion: /\.onion$/.test(new URL(endpoint).hostname),
          }))
        : [],
      lan: { enabled: dir.lan, peers: this.messenger?.lanPeers() ?? [] },
    };
  }

  async channel(input: unknown): Promise<ChannelView> {
    const a = ChannelActionSchema.parse(input);
    const m = this.messenger;
    if (!m) throw new Error('Encrypted messaging isn’t running on this device.');
    if (a.kind === 'get') return m.channel(a.channelId);
    return m.sendToChannel(a.spaceId, a.channelId, a.text);
  }

  get publicKey() {
    return toBase64Url(this.key.publicKey);
  }

  get fingerprint() {
    return fingerprint(this.publicKey);
  }

  private challenge(net: Transport) {
    return call(net, '/v1/auth/challenge', { method: 'POST', body: JSON.stringify({ devicePublicKey: this.publicKey }) }, (v) =>
      ChallengeResponse.parse(v),
    );
  }

  private authed<T>(path: string, init: Init, parse: (v: unknown) => T): Promise<T> {
    const s = this.session;
    if (!s) throw new Error('Not signed in.');
    return call(s.net, path, { ...init, headers: { ...init.headers, authorization: `Bearer ${s.token}` } }, parse);
  }

  private post<T>(path: string, body: unknown, parse: (v: unknown) => T = none as () => T): Promise<T> {
    return this.authed(path, { method: 'POST', body: JSON.stringify(body) }, parse);
  }

  async signup(input: SignupInput): Promise<{ account: AccountView; recoveryKey: string }> {
    const { transport: net, server } = await this.connect(input.serverUrl);
    const username = input.username.trim();
    // The recovery key is never stored: it is shown once for the user to write down.
    const recovery = generateDeviceKeyPair();
    const recoveryPublicKey = toBase64Url(recovery.publicKey);
    const c = await this.challenge(net);
    const session = await call(
      net,
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
    this.signedIn(net, server, session);
    await this.startMessenger();
    return { account: await this.me(), recoveryKey: formatRecoveryKey(recovery.secretKey) };
  }

  async login(serverUrl: string): Promise<AccountView> {
    const { transport, server } = await this.connect(serverUrl);
    return this.loginWith(transport, server);
  }

  private async loginWith(net: Transport, server: KnownServer): Promise<AccountView> {
    const c = await this.challenge(net);
    const session = await call(
      net,
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
    this.signedIn(net, server, session);
    await this.startMessenger();
    return this.me();
  }

  async logout(): Promise<void> {
    this.messenger?.stop();
    if (this.session) await this.post('/v1/auth/logout', {}).catch(none);
    this.endSession();
    this.lookedUp = undefined;
  }

  async requestLink(input: { serverUrl: string; username: string; deviceName: string }): Promise<LinkTicket> {
    const { transport: net, server } = await this.connect(input.serverUrl);
    const username = input.username.trim();
    const deviceName = input.deviceName.trim();
    const c = await this.challenge(net);
    const res = await call(
      net,
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
    this.waitingLink?.net.close();
    this.waitingLink = { net, server };
    const code = res.pairingCode;
    return { pairingCode: `${code.slice(0, 5)}-${code.slice(5)}`, fingerprint: this.fingerprint, expiresAt: res.expiresAt };
  }

  /** The renderer polls this; a poll that lands while the previous one is still signing in shares its result. */
  checkLink(): Promise<AccountView | null> {
    if (this.checking) return this.checking;
    const p = (this.checking = this.checkLinkOnce().finally(() => {
      if (this.checking === p) this.checking = undefined;
    }));
    return p;
  }

  private async checkLinkOnce(): Promise<AccountView | null> {
    const waiting = this.waitingLink;
    if (!waiting) throw new Error('This device is not waiting for approval.');
    const { approved } = await call(
      waiting.net,
      '/v1/device-links/status',
      { method: 'POST', body: JSON.stringify({ devicePublicKey: this.publicKey }) },
      (v) => z.object({ approved: z.boolean() }).parse(v),
    );
    if (!approved) return null;
    this.waitingLink = undefined;
    try {
      return await this.loginWith(waiting.net, waiting.server);
    } catch (err) {
      // Let the next poll try signing in again instead of forgetting the approval.
      this.waitingLink = waiting;
      throw err;
    }
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
      this.endSession();
      throw new Error('This device was revoked and signed out.');
    }
    return me;
  }

  async recover(input: RecoverInput): Promise<{ account: AccountView; recoveryKey: string }> {
    const { transport: net, server } = await this.connect(input.serverUrl);
    const username = input.username.trim();
    const recoverySecret = parseRecoveryKey(input.recoveryKey);
    const c = await this.challenge(net);
    const payload = recoverPayload(c.nonce, username, this.publicKey);
    const session = await call(
      net,
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
    this.signedIn(net, server, session);
    await this.startMessenger();
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

  /**
   * Server actions. Reads are remembered, so the server list and channels still
   * show (read-only) while the server is unreachable and messages go over the
   * local network.
   */
  async space(action: unknown): Promise<unknown> {
    const key = JSON.stringify(action);
    const readOnly = typeof action === 'object' && action !== null && ['list', 'get'].includes((action as { kind?: string }).kind ?? '');
    try {
      const value = await runSpaceAction(action, (method, path, body, parse) =>
        this.authed(path, { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }, parse),
      );
      if (readOnly) this.spaceCache.set(key, value);
      return value;
    } catch (err) {
      if (readOnly && err instanceof UnreachableError && this.spaceCache.has(key)) return this.spaceCache.get(key);
      throw err;
    }
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
