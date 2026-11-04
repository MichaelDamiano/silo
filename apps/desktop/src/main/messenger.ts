import { randomUUID } from 'node:crypto';
import {
  ChannelMessageList,
  ChannelMessagePayload,
  DirectMessagePayload,
  EnvelopeList,
  PairwisePayload,
  SpaceDevicesResponse,
  MismatchedDevices,
  PreKeyCount,
  UploadKeysResponse,
  UserKeysResponse,
  SpaceList,
  type DeviceBundle,
  type Envelope,
  type LanFrame,
} from '@silo/protocol';
import { IdentityChangedError, MissingSenderKeyError, SignalDevice, type StateStore, type Target } from '@silo/signal';
import { z } from 'zod';
import type { AppEvent, ChannelMessageView, ChannelView, Conversation, ConversationSummary, DmMessage } from '../shared/ipc.js';
import type { ChannelMessage } from '@silo/protocol';
import type { Vault } from './vault.js';
import type { WebSocket } from 'undici';
import { LanNode, type PeerDevice } from './lan.js';
import { UnreachableError } from './transport.js';

const PREKEY_LOW_WATER = 20;
const DeviceList = z.object({
  devices: z.array(z.object({ deviceId: z.uuid(), signalDeviceId: z.number().int(), publicKey: z.string().optional() })),
});
const DIRECTORY_REFRESH_MS = 5 * 60_000;
const LAN_NOTE = 'Sent over the local network. It will reach everyone else when the server is back.';

/** Everyone we can message, remembered so the app can still work over the local network when the server is down. */
interface Directory {
  devices: Record<string, PeerDevice>;
  /** Member devices of each server, by space id. */
  spaces: Record<string, string[]>;
}

/** Messages that only went over the local network, to send through the server once it's back. */
type OutboxItem = { kind: 'dm'; payload: DirectMessagePayload } | { kind: 'channel'; payload: ChannelMessagePayload };

interface Meta {
  deviceId: string;
  signalDeviceId: number;
}

interface History {
  conversations: Record<string, { peerUsername: string; messages: DmMessage[] }>;
}

/** How long a channel message may wait for its sender's key before we give up on it. */
const PENDING_MAX_MS = 7 * 24 * 60 * 60 * 1000;
const WAITING_FOR_KEY = 'Waiting for the sender’s key to decrypt this message…';

interface Channels {
  /** The device this state belongs to; it starts over if the device signs in as a different one. */
  deviceId: string;
  /** The last channel message seen from the server. */
  cursor: number;
  /** Our own sender key per channel, and which member devices already have it. */
  out: Record<string, { distributionId: string; sentTo: string[] }>;
  history: Record<string, ChannelMessageView[]>;
  /** Messages that arrived before their sender's key; retried after each sync. */
  pending: ChannelMessage[];
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
  /** Opens the live WebSocket on whichever server address is working. */
  socket(path: string): WebSocket;
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
  private channels!: Channels;
  private directory: Directory = { devices: {}, spaces: {} };
  private outbox: OutboxItem[] = [];
  private directoryAt = 0;
  private lan?: LanNode;

  private constructor(
    private readonly vault: Vault,
    private readonly signal: SignalDevice,
    private readonly api: Api,
    private readonly emit: (event: AppEvent) => void,
  ) {}

  static async start(vault: Vault, api: Api, emit: Messenger['emit']): Promise<Messenger> {
    const store: StateStore = { load: () => vault.read('signal'), save: (s) => vault.write('signal', s) };
    const signal = await SignalDevice.open(store);
    const m = new Messenger(vault, signal, api, emit);
    m.history = (await vault.read<History>('messages')) ?? { conversations: {} };
    const channels = await vault.read<Channels>('channels');
    m.channels = channels?.deviceId === api.deviceId ? channels : { deviceId: api.deviceId, cursor: 0, out: {}, history: {}, pending: [] };
    m.directory = (await vault.read<Directory>('directory')) ?? m.directory;
    m.outbox = (await vault.read<OutboxItem[]>('outbox')) ?? [];
    await m.publishKeys();
    m.connect();
    await m.sync();
    return m;
  }

  stop() {
    this.stopped = true;
    this.ws?.close();
    this.lan?.stop();
    this.lan = undefined;
  }

  /** Turns finding and linking with devices on the local network on or off. */
  async setLan(enabled: boolean) {
    if (!enabled || this.stopped) {
      this.lan?.stop();
      this.lan = undefined;
      this.emit({ type: 'lan', peers: [] });
      return;
    }
    if (this.lan) return;
    const lan = new LanNode({
      deviceId: this.api.deviceId,
      sign: (p) => this.api.sign(p),
      lookup: (id) => this.directory.devices[id],
      onFrame: (peer, frame) => void this.onLanFrame(peer, frame),
      onPeersChanged: () => this.emit({ type: 'lan', peers: this.lanPeers() }),
    });
    this.lan = lan;
    await lan.start();
  }

  lanPeers(): string[] {
    return [...new Set((this.lan?.peers() ?? []).map((p) => (p.userId === this.api.userId ? 'your other device' : p.username)))];
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
    const ws = this.api.socket('/v1/live');
    this.ws = ws;
    ws.addEventListener('open', () => {
      this.retry = 1000;
      ws.send(JSON.stringify({ token: this.api.token }));
    });
    ws.addEventListener('message', (ev) => {
      try {
        const { type } = JSON.parse(String(ev.data)) as { type?: string };
        if (type === 'envelopes' || type === 'channel') void this.sync();
      } catch {
        // Ignore anything we don't understand.
      }
    });
    ws.addEventListener('close', (ev) => {
      if (this.stopped || ev.code === 4001) return;
      // A sync goes over HTTPS, which moves to another address if this one is down.
      void this.sync();
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
          for (const e of envelopes) await this.receiveEnvelope(e, touched);
          await this.vault.write('messages', this.history);
          // Only acknowledge after the messages are safely written to disk.
          await this.api.request('POST', '/v1/messages/ack', { ids: envelopes.map((e) => e.id) }, () => null);
          for (const id of touched) this.emit({ type: 'messages', peerUserId: id });
        }
        await this.syncChannels();
      } while (this.again);
      await this.topUpPreKeys();
      await this.flushOutbox();
      await this.refreshDirectory().catch(() => undefined);
    })()
      // Being offline isn't worth a pop-up: the app keeps trying, and the connection panel shows it.
      .catch((err: Error) => {
        if (!(err instanceof UnreachableError)) this.emit({ type: 'error', message: err.message });
      })
      .finally(() => {
        this.syncing = undefined;
      });
    return this.syncing;
  }

  private async receiveEnvelope(e: Envelope, touched: Set<string>) {
    const fromMe = e.senderUserId === this.api.userId;
    let peer = { id: e.senderUserId, name: e.senderUsername };
    let msg: DmMessage;
    try {
      const payload = PairwisePayload.parse(JSON.parse(new TextDecoder().decode(await this.signal.decrypt(e))));
      if (payload.kind === 'senderKey') {
        // A member handing us their key for a channel. The pairwise session proves which device it's from.
        await this.signal.processSenderKeyDistribution(e.senderUserId, e.senderSignalDeviceId, payload.skdm);
        return;
      }
      // A copy from one of our own devices belongs to the conversation it was sent in.
      if (fromMe) peer = { id: payload.peerUserId, name: payload.peerUsername };
      msg = { id: payload.id, from: fromMe ? 'me' : 'them', text: payload.text, sentAt: payload.sentAt };
    } catch (err) {
      if (fromMe) return;
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

  /** Something arrived from a linked device on the local network. Who sent it comes from the link, not the frame. */
  private async onLanFrame(peer: PeerDevice, frame: LanFrame) {
    const now = new Date().toISOString();
    const sender = { senderUserId: peer.userId, senderUsername: peer.username, senderDeviceId: peer.deviceId, senderSignalDeviceId: peer.signalDeviceId };
    try {
      if (frame.t === 'envelope') {
        const touched = new Set<string>();
        await this.receiveEnvelope({ id: randomUUID(), ...sender, type: frame.type, body: frame.body, receivedAt: now }, touched);
        await this.vault.write('messages', this.history);
        for (const id of touched) this.emit({ type: 'messages', peerUserId: id });
      } else {
        if (!this.directory.spaces[frame.spaceId]?.includes(peer.deviceId)) return;
        const touched = new Set<string>();
        // A negative number keeps local-network messages apart from the server's sequence.
        const seq = -(Date.now() * 1000 + Math.floor(Math.random() * 1000));
        await this.receiveChannel({ seq, spaceId: frame.spaceId, channelId: frame.channelId, ...sender, body: frame.body, receivedAt: now }, touched);
        await this.vault.write('channels', this.channels);
        for (const id of touched) this.emit({ type: 'channel', channelId: id });
      }
    } catch (err) {
      this.emit({ type: 'error', message: `A message from the local network couldn't be read: ${(err as Error).message}` });
    }
  }

  /** Remembers every device we share a server with, and their login keys, for use when the server is unreachable. */
  private async refreshDirectory(force = false) {
    if (!force && Date.now() - this.directoryAt < DIRECTORY_REFRESH_MS) return;
    const { spaces } = await this.api.request('GET', '/v1/spaces', undefined, (v) => SpaceList.parse(v));
    const next: Directory = { devices: {}, spaces: {} };
    for (const space of spaces) {
      const { devices } = await this.api.request('GET', `/v1/spaces/${space.id}/devices`, undefined, (v) => SpaceDevicesResponse.parse(v));
      this.remember(next, space.id, devices);
    }
    this.directory = next;
    this.directoryAt = Date.now();
    await this.vault.write('directory', this.directory);
  }

  private remember(dir: Directory, spaceId: string, devices: { userId: string; username: string; deviceId: string; signalDeviceId: number; publicKey: string }[]) {
    dir.spaces[spaceId] = devices.map((d) => d.deviceId);
    for (const d of devices) dir.devices[d.deviceId] = d;
  }

  private async saveOutbox() {
    await this.vault.write('outbox', this.outbox);
  }

  /** Sends anything that only went over the local network through the server, now that it's reachable again. */
  private async flushOutbox() {
    while (this.outbox.length) {
      const item = this.outbox[0]!;
      try {
        if (item.kind === 'dm') {
          await this.sendDmOnline(item.payload);
          this.clearNote(this.history.conversations[item.payload.peerUserId]?.messages, item.payload.id);
          await this.vault.write('messages', this.history);
          this.emit({ type: 'messages', peerUserId: item.payload.peerUserId });
        } else {
          await this.sendChannelOnline(item.payload);
          this.clearNote(this.channels.history[item.payload.channelId], item.payload.id);
          await this.vault.write('channels', this.channels);
          this.emit({ type: 'channel', channelId: item.payload.channelId });
        }
      } catch (err) {
        if (err instanceof UnreachableError) return;
        // Something permanent, like leaving the server; don't retry it forever.
        this.emit({ type: 'error', message: `A message sent over the local network couldn't be synced: ${(err as Error).message}` });
      }
      this.outbox.shift();
      await this.saveOutbox();
    }
  }

  private clearNote(list: { id: string; note?: string }[] | undefined, id: string) {
    const m = list?.find((x) => x.id === id);
    if (m) delete m.note;
  }

  /** Our devices and theirs that are linked on the local network and that we already have a Signal session with. */
  private lanTargets(deviceIds: string[]): Target[] {
    return deviceIds
      .map((id) => this.directory.devices[id])
      .filter((d): d is PeerDevice => !!d && d.deviceId !== this.api.deviceId && !!this.lan?.isConnected(d.deviceId))
      .filter((d) => this.signal.hasSession(d.userId, d.signalDeviceId))
      .map((d) => ({ userId: d.userId, deviceId: d.deviceId, signalDeviceId: d.signalDeviceId }));
  }

  private noLanPeers(): Error {
    return new Error(
      this.lan
        ? 'The server is unreachable and none of the people here are on your local network right now.'
        : 'The server is unreachable. Turn on local network in Connection settings to reach people nearby.',
    );
  }

  channel(channelId: string): ChannelView {
    return { channelId, messages: this.channels.history[channelId] ?? [] };
  }

  /** Fetches new channel messages, then retries any that were waiting for a sender key. */
  private async syncChannels() {
    const touched = new Set<string>();
    const retry = this.channels.pending;
    this.channels.pending = [];
    for (const m of retry) await this.receiveChannel(m, touched);
    for (;;) {
      const { messages } = await this.api.request('GET', `/v1/channel-messages?after=${this.channels.cursor}`, undefined, (v) =>
        ChannelMessageList.parse(v),
      );
      if (!messages.length) break;
      for (const m of messages) await this.receiveChannel(m, touched);
      this.channels.cursor = Math.max(this.channels.cursor, ...messages.map((m) => m.seq));
      await this.vault.write('channels', this.channels);
    }
    if (retry.length || touched.size) await this.vault.write('channels', this.channels);
    for (const id of touched) this.emit({ type: 'channel', channelId: id });
  }

  private async receiveChannel(m: ChannelMessage, touched: Set<string>) {
    const list = (this.channels.history[m.channelId] ??= []);
    const placeholder = `srv-${m.seq}`;
    const base = { from: 'them' as const, senderUserId: m.senderUserId, senderUsername: m.senderUsername };
    let msg: ChannelMessageView;
    try {
      const { plaintext } = await this.signal.groupDecrypt(m.senderUserId, m.senderSignalDeviceId, m.body);
      const p = ChannelMessagePayload.parse(JSON.parse(new TextDecoder().decode(plaintext)));
      // The server says where a message belongs; the sender's signed payload has to agree.
      if (p.channelId !== m.channelId || p.spaceId !== m.spaceId) throw new Error('channel mismatch');
      msg = { ...base, id: p.id, text: p.text, sentAt: p.sentAt, from: m.senderUserId === this.api.userId ? 'me' : 'them' };
    } catch (err) {
      const fresh = Date.now() - Date.parse(m.receivedAt) < PENDING_MAX_MS;
      if (err instanceof MissingSenderKeyError && fresh) {
        this.channels.pending.push(m);
        if (list.some((x) => x.id === placeholder)) return;
        msg = { ...base, id: placeholder, text: '', sentAt: m.receivedAt, error: WAITING_FOR_KEY };
      } else {
        msg = {
          ...base,
          id: placeholder,
          text: '',
          sentAt: m.receivedAt,
          error: err instanceof MissingSenderKeyError ? 'The key for this message never arrived.' : "This message couldn't be decrypted.",
        };
      }
    }
    const i = list.findIndex((x) => x.id === placeholder);
    if (i >= 0) list.splice(i, 1);
    if (!list.some((x) => x.id === msg.id)) list.push(msg);
    list.sort((a, b) => a.sentAt.localeCompare(b.sentAt));
    touched.add(m.channelId);
  }

  /**
   * Sends to a channel. Our sender key goes to any member device that doesn't have
   * it yet. If a device left the server, the key is replaced first so it can't read on.
   */
  async sendToChannel(spaceId: string, channelId: string, text: string): Promise<ChannelView> {
    const payload: ChannelMessagePayload = {
      v: 1,
      kind: 'channel',
      id: randomUUID(),
      spaceId,
      channelId,
      sentAt: new Date().toISOString(),
      text: ChannelMessagePayload.shape.text.parse(text.trim()),
    };
    let note: string | undefined;
    try {
      await this.sendChannelOnline(payload);
    } catch (err) {
      if (!(err instanceof UnreachableError)) throw err;
      await this.sendChannelLan(payload);
      note = LAN_NOTE;
    }
    const list = (this.channels.history[channelId] ??= []);
    list.push({
      id: payload.id,
      from: 'me',
      senderUserId: this.api.userId,
      senderUsername: 'You',
      text: payload.text,
      sentAt: payload.sentAt,
      ...(note ? { note } : {}),
    });
    await this.vault.write('channels', this.channels);
    return this.channel(channelId);
  }

  private async sendChannelOnline(payload: ChannelMessagePayload) {
    const { spaceId, channelId } = payload;
    for (let attempt = 0; ; attempt++) {
      try {
        await this.shareSenderKey(spaceId, channelId);
        break;
      } catch (err) {
        if (err instanceof HttpStatusError && err.status === 409 && attempt === 0) continue;
        throw err;
      }
    }
    const { distributionId } = this.channels.out[channelId]!;
    const body = await this.signal.groupEncrypt(distributionId, new TextEncoder().encode(JSON.stringify(payload)));
    await this.api.request('POST', `/v1/channels/${channelId}/messages`, { body }, () => null);
  }

  /**
   * Sends a channel message straight to member devices linked on the local network.
   * Any of them without our sender key get it first over their pairwise session.
   */
  private async sendChannelLan(payload: ChannelMessagePayload) {
    const { spaceId, channelId } = payload;
    const targets = this.lanTargets(this.directory.spaces[spaceId] ?? []);
    if (!targets.length) throw this.noLanPeers();
    let out = this.channels.out[channelId];
    if (!out) out = this.channels.out[channelId] = { distributionId: randomUUID(), sentTo: [] };
    const need = targets.filter((t) => !out.sentTo.includes(t.deviceId));
    if (need.length) {
      const skdm = await this.signal.senderKeyDistribution(out.distributionId);
      const plaintext = new TextEncoder().encode(
        JSON.stringify({ v: 1, kind: 'senderKey', spaceId, channelId, distributionId: out.distributionId, skdm }),
      );
      for (const m of await this.signal.encrypt(plaintext, need)) this.lan!.send(m.deviceId, { t: 'envelope', type: m.type, body: m.body });
      out.sentTo.push(...need.map((t) => t.deviceId));
    }
    const body = await this.signal.groupEncrypt(out.distributionId, new TextEncoder().encode(JSON.stringify(payload)));
    for (const t of targets) this.lan!.send(t.deviceId, { t: 'channel', spaceId, channelId, body });
    this.outbox.push({ kind: 'channel', payload });
    await this.saveOutbox();
  }

  private async shareSenderKey(spaceId: string, channelId: string) {
    const { devices } = await this.api.request('GET', `/v1/spaces/${spaceId}/devices`, undefined, (v) => SpaceDevicesResponse.parse(v));
    this.remember(this.directory, spaceId, devices);
    const current = new Set(devices.map((d) => d.deviceId));
    let out = this.channels.out[channelId];
    if (!out || out.sentTo.some((id) => !current.has(id))) {
      out = { distributionId: randomUUID(), sentTo: [] };
      this.channels.out[channelId] = out;
    }
    const sent = new Set(out.sentTo);
    const need = devices.filter((d) => !sent.has(d.deviceId));
    if (!need.length) return;

    const skdm = await this.signal.senderKeyDistribution(out.distributionId);
    const plaintext = new TextEncoder().encode(
      JSON.stringify({ v: 1, kind: 'senderKey', spaceId, channelId, distributionId: out.distributionId, skdm }),
    );
    const targets: Target[] = [];
    for (const userId of new Set(need.map((d) => d.userId))) {
      targets.push(...(await this.targetsFor(userId, need.filter((d) => d.userId === userId))));
    }
    const messages = await this.signal.encrypt(plaintext, targets);
    for (let i = 0; i < messages.length; i += 500) {
      await this.api.request('POST', `/v1/spaces/${spaceId}/sender-keys`, { messages: messages.slice(i, i + 500) }, () => null);
    }
    out.sentTo.push(...need.map((d) => d.deviceId));
    await this.vault.write('channels', this.channels);
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
    let note: string | undefined;
    try {
      await this.sendDmOnline(payload);
    } catch (err) {
      if (!(err instanceof UnreachableError)) throw err;
      await this.sendDmLan(payload);
      note = LAN_NOTE;
    }
    this.store(peerUserId, peerUsername, { id: payload.id, from: 'me', text: payload.text, sentAt: payload.sentAt, ...(note ? { note } : {}) });
    await this.vault.write('messages', this.history);
    return this.conversation(peerUserId);
  }

  private async sendDmOnline(payload: DirectMessagePayload) {
    const { peerUserId, peerUsername } = payload;
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
  }

  /** Sends a DM straight to the recipient's devices, and our own, that are linked on the local network. */
  private async sendDmLan(payload: DirectMessagePayload) {
    const ids = Object.values(this.directory.devices)
      .filter((d) => d.userId === payload.peerUserId || d.userId === this.api.userId)
      .map((d) => d.deviceId);
    const targets = this.lanTargets(ids);
    if (!targets.some((t) => t.userId === payload.peerUserId)) throw this.noLanPeers();
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    for (const m of await this.signal.encrypt(plaintext, targets)) this.lan!.send(m.deviceId, { t: 'envelope', type: m.type, body: m.body });
    this.outbox.push({ kind: 'dm', payload });
    await this.saveOutbox();
  }

  private async targetsFor(userId: string, only?: { deviceId: string; signalDeviceId: number }[]): Promise<Target[]> {
    const devices =
      only ?? (await this.api.request('GET', `/v1/users/${userId}/devices`, undefined, (v) => DeviceList.parse(v))).devices;
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
