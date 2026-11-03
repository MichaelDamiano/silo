import { randomUUID } from 'node:crypto';
import {
  DirectMessagePayload,
  EnvelopeList,
  MismatchedDevices,
  PreKeyCount,
  UploadKeysResponse,
  UserKeysResponse,
  type DeviceBundle,
} from '@silo/protocol';
import { IdentityChangedError, SignalDevice, type StateStore, type Target } from '@silo/signal';
import { z } from 'zod';
import type { Conversation, ConversationSummary, DmMessage } from '../shared/ipc.js';
import type { Vault } from './vault.js';

const PREKEY_LOW_WATER = 20;
const DeviceList = z.object({ devices: z.array(z.object({ deviceId: z.uuid(), signalDeviceId: z.number().int() })) });

interface Meta {
  deviceId: string;
  signalDeviceId: number;
}

interface History {
  conversations: Record<string, { peerUsername: string; messages: DmMessage[] }>;
}

export class HttpStatusError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: unknown,
    message: string,
  ) {
    super(message);
  }
}

export interface Api {
  base: string;
  token: string;
  userId: string;
  deviceId: string;
  request<T>(method: 'GET' | 'POST' | 'PUT', path: string, body: unknown, parse: (v: unknown) => T): Promise<T>;
  /** Signs with this device's Ed25519 login key. */
  sign(payload: Uint8Array): string;
}

/**
 * Sends and receives end-to-end encrypted direct messages for one signed-in device.
 * Plaintext only ever exists here, in the main process, and in the encrypted vault.
 */
export class Messenger {
  private ws?: WebSocket;
  private stopped = false;
  private retry = 1000;
  private syncing?: Promise<void>;
  private again = false;
  private history: History = { conversations: {} };

  private constructor(
    private readonly vault: Vault,
    private readonly signal: SignalDevice,
    private readonly api: Api,
    private readonly emit: (event: { type: 'messages'; peerUserId: string } | { type: 'error'; message: string }) => void,
  ) {}

  static async start(vault: Vault, api: Api, emit: Messenger['emit']): Promise<Messenger> {
    const store: StateStore = { load: () => vault.read('signal'), save: (s) => vault.write('signal', s) };
    const signal = await SignalDevice.open(store);
    const m = new Messenger(vault, signal, api, emit);
    m.history = (await vault.read<History>('messages')) ?? { conversations: {} };
    await m.publishKeys();
    m.connect();
    await m.sync();
    return m;
  }

  stop() {
    this.stopped = true;
    this.ws?.close();
  }

  /** Publishes this device's Signal keys once, and tops up one-time pre-keys when they run low. */
  private async publishKeys() {
    let meta = await this.vault.read<Meta>('signal-meta');
    if (meta?.deviceId !== this.api.deviceId) {
      const upload = await this.signal.keyUpload(this.api.deviceId, (p) => this.api.sign(p));
      const res = await this.api.request('PUT', '/v1/keys', upload, (v) => UploadKeysResponse.parse(v));
      meta = { deviceId: this.api.deviceId, signalDeviceId: res.signalDeviceId };
      await this.vault.write('signal-meta', meta);
    }
    this.signal.setAddress(this.api.userId, meta.signalDeviceId);
    await this.topUpPreKeys();
  }

  private async topUpPreKeys() {
    const { count } = await this.api.request('GET', '/v1/keys/count', undefined, (v) => PreKeyCount.parse(v));
    if (count < PREKEY_LOW_WATER) {
      const oneTimePreKeys = await this.signal.morePreKeys();
      await this.api.request('POST', '/v1/keys/prekeys', { oneTimePreKeys }, () => null);
    }
  }

  private connect() {
    if (this.stopped) return;
    const url = this.api.base.replace(/^http/, 'ws') + '/v1/live';
    const ws = new WebSocket(url);
    this.ws = ws;
    ws.addEventListener('open', () => {
      this.retry = 1000;
      ws.send(JSON.stringify({ token: this.api.token }));
    });
    ws.addEventListener('message', (ev) => {
      try {
        if (JSON.parse(String(ev.data)).type === 'envelopes') void this.sync();
      } catch {
        // Ignore anything we don't understand.
      }
    });
    ws.addEventListener('close', (ev) => {
      if (this.stopped || ev.code === 4001) return;
      // Reconnect with backoff, and catch up on anything missed while offline.
      setTimeout(() => this.connect(), this.retry);
      this.retry = Math.min(this.retry * 2, 30_000);
    });
  }

  conversations(): ConversationSummary[] {
    return Object.entries(this.history.conversations)
      .map(([peerUserId, c]) => ({ peerUserId, peerUsername: c.peerUsername, last: c.messages.at(-1) ?? null }))
      .sort((a, b) => (b.last?.sentAt ?? '').localeCompare(a.last?.sentAt ?? ''));
  }

  conversation(peerUserId: string, peerUsername?: string): Conversation {
    const c = this.history.conversations[peerUserId];
    return { peerUserId, peerUsername: c?.peerUsername ?? peerUsername ?? 'unknown', messages: c?.messages ?? [] };
  }

  /** Fetches, decrypts and stores everything waiting for this device. Runs one at a time. */
  sync(): Promise<void> {
    if (this.syncing) {
      this.again = true;
      return this.syncing;
    }
    this.syncing = (async () => {
      do {
        this.again = false;
        for (;;) {
          const { envelopes } = await this.api.request('GET', '/v1/messages', undefined, (v) => EnvelopeList.parse(v));
          if (!envelopes.length) break;
          const touched = new Set<string>();
          for (const e of envelopes) {
            const fromMe = e.senderUserId === this.api.userId;
            let peer = { id: e.senderUserId, name: e.senderUsername };
            let msg: DmMessage;
            try {
              const payload = DirectMessagePayload.parse(JSON.parse(new TextDecoder().decode(await this.signal.decrypt(e))));
              // A copy from one of our own devices belongs to the conversation it was sent in.
              if (fromMe) peer = { id: payload.peerUserId, name: payload.peerUsername };
              msg = { id: payload.id, from: fromMe ? 'me' : 'them', text: payload.text, sentAt: payload.sentAt };
            } catch (err) {
              if (fromMe) continue;
              msg = {
                id: e.id,
                from: 'them',
                text: '',
                sentAt: e.receivedAt,
                error:
                  err instanceof IdentityChangedError
                    ? `${e.senderUsername}'s encryption key changed, so this message was blocked.`
                    : "This message couldn't be decrypted.",
              };
            }
            this.store(peer.id, peer.name, msg);
            touched.add(peer.id);
          }
          await this.vault.write('messages', this.history);
          // Only acknowledge after the messages are safely written to disk.
          await this.api.request('POST', '/v1/messages/ack', { ids: envelopes.map((e) => e.id) }, () => null);
          for (const id of touched) this.emit({ type: 'messages', peerUserId: id });
        }
      } while (this.again);
      await this.topUpPreKeys();
    })()
      .catch((err: Error) => this.emit({ type: 'error', message: err.message }))
      .finally(() => {
        this.syncing = undefined;
      });
    return this.syncing;
  }

  private store(peerUserId: string, peerUsername: string, msg: DmMessage) {
    const c = (this.history.conversations[peerUserId] ??= { peerUsername, messages: [] });
    c.peerUsername = peerUsername;
    if (c.messages.some((m) => m.id === msg.id)) return;
    c.messages.push(msg);
    c.messages.sort((a, b) => a.sentAt.localeCompare(b.sentAt));
  }

  /** Encrypts a DM separately for each of the recipient's devices and each of our other devices. */
  async send(peerUserId: string, peerUsername: string, text: string): Promise<Conversation> {
    const payload: DirectMessagePayload = {
      v: 1,
      kind: 'dm',
      id: randomUUID(),
      peerUserId,
      peerUsername,
      sentAt: new Date().toISOString(),
      text: DirectMessagePayload.shape.text.parse(text.trim()),
    };
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    for (let attempt = 0; ; attempt++) {
      const targets = [...(await this.targetsFor(peerUserId)), ...(await this.targetsFor(this.api.userId))];
      if (!targets.some((t) => t.userId === peerUserId)) {
        throw new Error(`${peerUsername} hasn't signed in on a device that can receive encrypted messages yet.`);
      }
      const messages = await this.signal.encrypt(plaintext, targets);
      try {
        await this.api.request('POST', '/v1/messages', { recipientUserId: peerUserId, messages }, () => null);
        break;
      } catch (err) {
        // Someone added or removed a device since we last looked; refresh and try once more.
        if (err instanceof HttpStatusError && err.status === 409 && MismatchedDevices.safeParse(err.body).success && attempt === 0) continue;
        throw err;
      }
    }
    this.store(peerUserId, peerUsername, { id: payload.id, from: 'me', text: payload.text, sentAt: payload.sentAt });
    await this.vault.write('messages', this.history);
    return this.conversation(peerUserId);
  }

  private async targetsFor(userId: string): Promise<Target[]> {
    const { devices } = await this.api.request('GET', `/v1/users/${userId}/devices`, undefined, (v) => DeviceList.parse(v));
    const needBundles = devices.filter((d) => !this.signal.hasSession(userId, d.signalDeviceId));
    let bundles: DeviceBundle[] = [];
    if (needBundles.length) {
      const res = await this.api.request(
        'GET',
        `/v1/users/${userId}/keys?devices=${needBundles.map((d) => d.deviceId).join(',')}`,
        undefined,
        (v) => UserKeysResponse.parse(v),
      );
      bundles = res.devices;
    }
    return devices.map((d) => ({
      userId,
      deviceId: d.deviceId,
      signalDeviceId: d.signalDeviceId,
      bundle: bundles.find((b) => b.deviceId === d.deviceId),
    }));
  }
}
