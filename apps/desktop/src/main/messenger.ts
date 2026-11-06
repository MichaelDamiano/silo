import { randomUUID } from 'node:crypto';
import {
  ACCESS_KEY_HEADER,
  AccessKey,
  SEALED_TYPE,
  SealedMismatch,
  SenderCertificateResponse,
  ChannelMessageList,
  ChannelMessagePayload,
  ChannelPayload,
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
  type DirectPayload,
  type DirectReactionPayload,
  type ChannelReactionPayload,
  Emoji,
  type ReplyRef,
  type LanFrame,
  type SealedEnvelope,
} from '@silo/protocol';
import { IdentityChangedError, MissingSenderKeyError, SignalDevice, safetyNumber, type StateStore, type Target } from '@silo/signal';
import { z } from 'zod';
import type { AppEvent, ChannelMessageView, ChannelView, Conversation, ConversationSummary, DmMessage, ReactionView, ReplyView } from '../shared/ipc.js';
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

/** How long before a sender certificate expires we fetch a new one. */
const CERTIFICATE_MARGIN_MS = 60 * 60 * 1000;

/**
 * Sealed sender state. People's access keys arrive inside their messages; with one,
 * our messages to them go sealed, so the server doesn't learn who sent them.
 */
interface Sealed {
  peers: Record<string, string>;
  certificate?: { certificate: string; expiresAt: string };
}

/** Messages that only went over the local network, to send through the server once it's back. */
type OutboxItem = { kind: 'dm'; payload: DirectPayload } | { kind: 'channel'; payload: ChannelPayload };

/** One person's latest say on one emoji. Kept even when taken back, so an older copy arriving late can't undo it. */
interface ReactionRecord {
  userId: string;
  username: string;
  emoji: string;
  at: string;
  on: boolean;
}

/** What is kept on disk for a message: the quote as the sender claimed it, and every reaction. */
interface Stored {
  reply?: ReplyRef;
  r?: ReactionRecord[];
}
type StoredDm = Omit<DmMessage, 'replyTo' | 'reactions'> & Stored;
type StoredChannelMessage = Omit<ChannelMessageView, 'replyTo' | 'reactions'> & Stored;

/** A reaction whose message hasn't arrived yet, such as one still waiting for its sender's key. */
interface PendingReaction {
  /** The conversation partner for DMs, the channel for channel messages. */
  where: string;
  messageId: string;
  rec: ReactionRecord;
}

/** Limits that keep one person from filling the vault with reactions. */
const MAX_REACTIONS_PER_MESSAGE = 300;
const MAX_PENDING_REACTIONS = 500;
const QUOTE_LENGTH = 200;
/** Shown in a quote instead of the text of a message from someone this account blocked. */
const BLOCKED_QUOTE = 'Message from someone you blocked.';

interface Meta {
  deviceId: string;
  signalDeviceId: number;
}

interface History {
  conversations: Record<string, { peerUsername: string; messages: StoredDm[] }>;
  pendingReactions?: PendingReaction[];
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
  history: Record<string, StoredChannelMessage[]>;
  /** Messages that arrived before their sender's key; retried after each sync. */
  pending: ChannelMessage[];
  pendingReactions?: PendingReaction[];
}

/** The start of a message, for quoting it in a reply. Cut on whole characters so an emoji isn't split. */
function excerpt(text: string): string {
  const chars = Array.from(text);
  return chars.length > QUOTE_LENGTH ? chars.slice(0, QUOTE_LENGTH).join('') + '…' : text;
}

/** Records a reaction unless a newer one from the same person for the same emoji is already there. */
function applyReaction(msg: Stored, rec: ReactionRecord) {
  const list = (msg.r ??= []);
  const i = list.findIndex((x) => x.userId === rec.userId && x.emoji === rec.emoji);
  if (i >= 0) {
    if (list[i]!.at > rec.at) return;
    list[i] = rec;
  } else if (list.length < MAX_REACTIONS_PER_MESSAGE) list.push(rec);
}

/** Moves any reactions that were waiting for this message onto it. */
function claimPending(pending: PendingReaction[] | undefined, where: string, msg: { id: string } & Stored): PendingReaction[] | undefined {
  if (!pending?.length) return pending;
  const rest: PendingReaction[] = [];
  for (const p of pending) {
    if (p.where === where && p.messageId === msg.id) applyReaction(msg, p.rec);
    else rest.push(p);
  }
  return rest;
}

function stash(pending: PendingReaction[] | undefined, p: PendingReaction): PendingReaction[] {
  const list = pending ?? [];
  list.push(p);
  return list.length > MAX_PENDING_REACTIONS ? list.slice(-MAX_PENDING_REACTIONS) : list;
}

/** A reply names the message it answers; forwarding marks a copy of a message sent somewhere else. */
export interface SendOptions {
  replyTo?: string;
  forwarded?: boolean;
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
  /** POSTs without signing in, on a connection no other request shares. */
  anonymous<T>(path: string, body: unknown, headers: Record<string, string>, parse: (v: unknown) => T): Promise<T>;
  /** The server's sealed sender trust root, from its signed identity, if it publishes one. */
  sealedSenderRoot(): string | undefined;
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
  /** People this account blocked. Their direct messages are dropped and their channel messages hidden. */
  private blocked = new Set<string>();
  private sealed: Sealed = { peers: {} };
  /** Our account's access key, which our messages hand to the people we write to. */
  private accessKey?: string;

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
    m.sealed = (await vault.read<Sealed>('sealed')) ?? m.sealed;
    await m.publishKeys();
    await m.refreshAccessKey().catch(() => undefined);
    m.connect();
    await m.sync();
    return m;
  }

  setBlocked(userIds: string[]) {
    this.blocked = new Set(userIds);
  }

  /**
   * The safety number for a conversation, over every device of both people as the
   * server lists them now. It is null until we've exchanged keys with all of them,
   * which happens once each person has sent the other a message.
   */
  async safety(peerUserId: string): Promise<{ number: string | null; theirDevices: number; myDevices: number; missing: number }> {
    const list = (userId: string) =>
      this.api.request('GET', `/v1/users/${userId}/devices`, undefined, (v) => DeviceList.parse(v)).then((r) => r.devices.map((d) => d.signalDeviceId));
    const [theirs, mine] = await Promise.all([list(peerUserId), list(this.api.userId)]);
    const theirKeys = this.signal.identityKeysOf(peerUserId, theirs);
    const myKeys = [this.signal.identityKey, ...this.signal.identityKeysOf(this.api.userId, mine)];
    const missing = [...theirKeys, ...myKeys].filter((k) => !k).length;
    return {
      number:
        missing || !theirKeys.length
          ? null
          : safetyNumber({ userId: this.api.userId, identityKeys: myKeys as string[] }, { userId: peerUserId, identityKeys: theirKeys as string[] }),
      theirDevices: theirs.length,
      myDevices: mine.length + 1,
      missing,
    };
  }

  /** Trusts whatever keys the server now has for this person. Only after checking with them outside Silo. */
  async acceptNewKeys(peerUserId: string) {
    await this.signal.forgetUser(peerUserId);
  }

  /** Our own decrypted copy of a channel message, by the server's sequence number. */
  channelMessage(channelId: string, seq: number): ChannelMessageView | undefined {
    const m = this.channels.history[channelId]?.find((x) => x.seq === seq);
    return m && this.channelView(channelId, m);
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
      .map(([peerUserId, c]) => {
        const last = c.messages.at(-1);
        return { peerUserId, peerUsername: c.peerUsername, last: last ? this.dmView(peerUserId, last) : null };
      })
      .sort((a, b) => (b.last?.sentAt ?? '').localeCompare(a.last?.sentAt ?? ''));
  }

  conversation(peerUserId: string, peerUsername?: string): Conversation {
    const c = this.history.conversations[peerUserId];
    return {
      peerUserId,
      peerUsername: c?.peerUsername ?? peerUsername ?? 'unknown',
      messages: (c?.messages ?? []).map((m) => this.dmView(peerUserId, m)),
    };
  }

  /** The people behind each emoji on a message, leaving out anyone hidden. */
  private reactionsView(records: ReactionRecord[] | undefined, hide?: (userId: string) => boolean): ReactionView[] | undefined {
    const groups = new Map<string, ReactionView>();
    for (const x of records ?? []) {
      if (!x.on || hide?.(x.userId)) continue;
      const g = groups.get(x.emoji) ?? { emoji: x.emoji, count: 0, mine: false, names: [] };
      g.count++;
      if (x.userId === this.api.userId) g.mine = true;
      g.names.push(x.userId === this.api.userId ? 'You' : x.username);
      groups.set(x.emoji, g);
    }
    return groups.size ? [...groups.values()] : undefined;
  }

  /**
   * A DM as the app shows it. A reply quotes our own copy of the original when we
   * have it, so the quote can't be made up; otherwise it shows the sender's claim, marked.
   */
  private dmView(peerUserId: string, m: StoredDm): DmMessage {
    const { reply, r, ...out } = m as StoredDm & Pick<DmMessage, 'replyTo' | 'reactions'>;
    const c = this.history.conversations[peerUserId];
    const peerName = c?.peerUsername ?? 'them';
    if (reply) {
      const orig = c?.messages.find((x) => x.id === reply.id);
      out.replyTo =
        orig && !orig.error
          ? { id: reply.id, author: orig.from === 'me' ? 'You' : peerName, text: excerpt(orig.text) }
          : {
              id: reply.id,
              author: reply.userId === this.api.userId ? 'You' : reply.userId === peerUserId ? peerName : 'someone else',
              text: reply.text,
              missing: true,
            };
    }
    const reactions = this.reactionsView(r);
    if (reactions) out.reactions = reactions;
    return out;
  }

  private channelView(channelId: string, m: StoredChannelMessage): ChannelMessageView {
    const { reply, r, ...out } = m as StoredChannelMessage & Pick<ChannelMessageView, 'replyTo' | 'reactions'>;
    const hidden = (userId: string) => userId !== this.api.userId && this.blocked.has(userId);
    if (hidden(m.senderUserId) && m.from !== 'me') out.blocked = true;
    if (reply) {
      const orig = this.channels.history[channelId]?.find((x) => x.id === reply.id);
      out.replyTo =
        orig && !orig.error
          ? { id: reply.id, author: orig.from === 'me' ? 'You' : orig.senderUsername, text: hidden(orig.senderUserId) ? BLOCKED_QUOTE : excerpt(orig.text) }
          : {
              id: reply.id,
              author: reply.userId === this.api.userId ? 'You' : (this.knownUsername(reply.userId) ?? 'unknown'),
              text: hidden(reply.userId) ? BLOCKED_QUOTE : reply.text,
              missing: true,
            };
    }
    const reactions = this.reactionsView(r, hidden);
    if (reactions) out.reactions = reactions;
    return out;
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
      if (this.api.sealedSenderRoot()) await this.certificate().catch(() => undefined);
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
    if (e.type === SEALED_TYPE) return this.receiveSealed(e, touched);
    let plaintext: Uint8Array | undefined;
    let failure: unknown;
    try {
      plaintext = await this.signal.decrypt(e);
    } catch (err) {
      failure = err;
    }
    await this.receivePlaintext(e, plaintext, failure, touched);
  }

  /**
   * A sealed message: the sender is only named inside, by a certificate our server
   * signed. Without a trust root, or if it can't be opened, nobody can be told about
   * it, so it is dropped; showing an error would let anyone with our key spam pop-ups.
   */
  private async receiveSealed(e: SealedEnvelope, touched: Set<string>) {
    const root = this.api.sealedSenderRoot();
    if (!root) return;
    let opened: Awaited<ReturnType<SignalDevice['sealedDecrypt']>>;
    try {
      opened = await this.signal.sealedDecrypt(e.body, root);
    } catch (err) {
      // Who it claims to be from isn't proven here, so only a name we already know is shown.
      const name = err instanceof IdentityChangedError ? this.knownUsername(err.userId) : undefined;
      if (name && !this.blocked.has((err as IdentityChangedError).userId)) {
        await this.receivePlaintext(
          { id: e.id, senderUserId: (err as IdentityChangedError).userId, senderUsername: name, senderSignalDeviceId: 0, receivedAt: e.receivedAt },
          undefined,
          err,
          touched,
        );
      }
      return;
    }
    const sender = {
      id: e.id,
      senderUserId: opened.senderUserId,
      senderUsername: opened.senderUsername ?? this.knownUsername(opened.senderUserId) ?? 'unknown',
      senderSignalDeviceId: opened.senderSignalDeviceId,
      receivedAt: e.receivedAt,
    };
    await this.receivePlaintext(sender, opened.plaintext, undefined, touched);
  }

  /** A name for someone from what this device already knows, without asking the server. */
  private knownUsername(userId: string): string | undefined {
    return (
      this.history.conversations[userId]?.peerUsername ?? Object.values(this.directory.devices).find((d) => d.userId === userId)?.username
    );
  }

  private async receivePlaintext(
    e: { id: string; senderUserId: string; senderUsername: string; senderSignalDeviceId: number; receivedAt: string },
    plaintext: Uint8Array | undefined,
    failure: unknown,
    touched: Set<string>,
  ) {
    const fromMe = e.senderUserId === this.api.userId;
    let peer = { id: e.senderUserId, name: e.senderUsername };
    let msg: StoredDm;
    try {
      if (!plaintext) throw failure;
      const payload = PairwisePayload.parse(JSON.parse(new TextDecoder().decode(plaintext)));
      if (payload.kind === 'senderKey') {
        // A member handing us their key for a channel. The pairwise session proves which device it's from.
        await this.signal.processSenderKeyDistribution(e.senderUserId, e.senderSignalDeviceId, payload.skdm);
        return;
      }
      // Blocked people's messages can still arrive over the local network or sealed; drop them here too.
      if (!fromMe && this.blocked.has(e.senderUserId)) return;
      if (!fromMe && payload.accessKey) await this.learnAccessKey(e.senderUserId, payload.accessKey);
      // A copy from one of our own devices belongs to the conversation it was sent in.
      if (fromMe) peer = { id: payload.peerUserId, name: payload.peerUsername };
      if (payload.kind === 'dmReaction') {
        // Signal proves who reacted; the message it points at has to be in our conversation with them.
        this.reactInDm(peer.id, payload.messageId, { userId: e.senderUserId, username: e.senderUsername, emoji: payload.emoji, at: payload.sentAt, on: payload.on });
        touched.add(peer.id);
        return;
      }
      msg = {
        id: payload.id,
        from: fromMe ? 'me' : 'them',
        text: payload.text,
        sentAt: payload.sentAt,
        ...(payload.replyTo ? { reply: payload.replyTo } : {}),
        ...(payload.forwarded ? { forwarded: true } : {}),
      };
    } catch (err) {
      if (fromMe || this.blocked.has(e.senderUserId)) return;
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

  private reactInDm(peerUserId: string, messageId: string, rec: ReactionRecord) {
    const target = this.history.conversations[peerUserId]?.messages.find((m) => m.id === messageId);
    if (target) applyReaction(target, rec);
    else this.history.pendingReactions = stash(this.history.pendingReactions, { where: peerUserId, messageId, rec });
  }

  private reactInChannel(channelId: string, messageId: string, rec: ReactionRecord) {
    const target = this.channels.history[channelId]?.find((m) => m.id === messageId);
    if (target) applyReaction(target, rec);
    else this.channels.pendingReactions = stash(this.channels.pendingReactions, { where: channelId, messageId, rec });
  }

  private async learnAccessKey(userId: string, key: string) {
    if (this.sealed.peers[userId] === key || !AccessKey.safeParse(key).success) return;
    this.sealed.peers[userId] = key;
    await this.vault.write('sealed', this.sealed);
  }

  private async refreshAccessKey() {
    this.accessKey = (await this.api.request('GET', '/v1/access-key', undefined, (v) => z.object({ accessKey: AccessKey }).parse(v))).accessKey;
  }

  /**
   * Replaces our access key, after blocking someone. Everyone else gets the new one
   * with our next message to them; until then they send to us the normal way.
   */
  async rotateAccessKey() {
    this.accessKey = (await this.api.request('POST', '/v1/access-key/rotate', {}, (v) => z.object({ accessKey: AccessKey }).parse(v))).accessKey;
  }

  /** A sender certificate for sealed messages, fetched ahead of time rather than just before a send. */
  private async certificate(): Promise<string> {
    const c = this.sealed.certificate;
    if (c && Date.parse(c.expiresAt) - Date.now() > CERTIFICATE_MARGIN_MS) return c.certificate;
    this.sealed.certificate = await this.api.request('GET', '/v1/certificate', undefined, (v) => SenderCertificateResponse.parse(v));
    await this.vault.write('sealed', this.sealed);
    return this.sealed.certificate.certificate;
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
    // Another of our devices may have replaced the access key.
    await this.refreshAccessKey().catch(() => undefined);
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
    return { channelId, messages: (this.channels.history[channelId] ?? []).map((m) => this.channelView(channelId, m)) };
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
    const base = { from: 'them' as const, senderUserId: m.senderUserId, senderUsername: m.senderUsername, ...(m.seq > 0 ? { seq: m.seq } : {}) };
    let msg: StoredChannelMessage;
    try {
      const { plaintext } = await this.signal.groupDecrypt(m.senderUserId, m.senderSignalDeviceId, m.body);
      const p = ChannelPayload.parse(JSON.parse(new TextDecoder().decode(plaintext)));
      // The server says where a message belongs; the sender's signed payload has to agree.
      if (p.channelId !== m.channelId || p.spaceId !== m.spaceId) throw new Error('channel mismatch');
      if (p.kind === 'reaction') {
        // It may have been waiting for its key behind a placeholder.
        const i = list.findIndex((x) => x.id === placeholder);
        if (i >= 0) list.splice(i, 1);
        this.reactInChannel(m.channelId, p.messageId, { userId: m.senderUserId, username: m.senderUsername, emoji: p.emoji, at: p.sentAt, on: p.on });
        touched.add(m.channelId);
        return;
      }
      msg = {
        ...base,
        id: p.id,
        text: p.text,
        sentAt: p.sentAt,
        from: m.senderUserId === this.api.userId ? 'me' : 'them',
        ...(p.replyTo ? { reply: p.replyTo } : {}),
        ...(p.forwarded ? { forwarded: true } : {}),
      };
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
    const known = list.find((x) => x.id === msg.id);
    // The same message can come over the local network first; the server's copy adds its number.
    if (known) known.seq ??= msg.seq;
    else {
      list.push(msg);
      this.channels.pendingReactions = claimPending(this.channels.pendingReactions, m.channelId, msg);
    }
    list.sort((a, b) => a.sentAt.localeCompare(b.sentAt));
    touched.add(m.channelId);
  }

  /**
   * Sends to a channel. Our sender key goes to any member device that doesn't have
   * it yet. If a device left the server, the key is replaced first so it can't read on.
   */
  async sendToChannel(spaceId: string, channelId: string, text: string, opts: SendOptions = {}): Promise<ChannelView> {
    const replyTo = opts.replyTo ? this.channelReplyRef(channelId, opts.replyTo) : undefined;
    const payload: ChannelMessagePayload = {
      v: 1,
      kind: 'channel',
      id: randomUUID(),
      spaceId,
      channelId,
      sentAt: new Date().toISOString(),
      text: ChannelMessagePayload.shape.text.parse(text.trim()),
      ...(replyTo ? { replyTo } : {}),
      ...(opts.forwarded ? { forwarded: true as const } : {}),
    };
    const note = await this.deliverChannel(payload);
    const list = (this.channels.history[channelId] ??= []);
    list.push({
      id: payload.id,
      from: 'me',
      senderUserId: this.api.userId,
      senderUsername: 'You',
      text: payload.text,
      sentAt: payload.sentAt,
      ...(replyTo ? { reply: replyTo } : {}),
      ...(opts.forwarded ? { forwarded: true } : {}),
      ...(note ? { note } : {}),
    });
    await this.vault.write('channels', this.channels);
    return this.channel(channelId);
  }

  /** Adds or takes back our reaction to a channel message, encrypted for the channel like a message. */
  async reactInChannelMessage(spaceId: string, channelId: string, messageId: string, emoji: string, on: boolean): Promise<ChannelView> {
    const target = this.channels.history[channelId]?.find((m) => m.id === messageId);
    if (!target || target.error) throw new Error('You can’t react to that message.');
    const payload: ChannelReactionPayload = {
      v: 1,
      kind: 'reaction',
      id: randomUUID(),
      spaceId,
      channelId,
      messageId,
      emoji: Emoji.parse(emoji),
      on,
      sentAt: new Date().toISOString(),
    };
    await this.deliverChannel(payload);
    applyReaction(target, { userId: this.api.userId, username: 'You', emoji: payload.emoji, at: payload.sentAt, on });
    await this.vault.write('channels', this.channels);
    return this.channel(channelId);
  }

  /** What a reply sends along about the message it answers. Only a message we could read can be replied to. */
  private channelReplyRef(channelId: string, messageId: string): ReplyRef {
    const m = this.channels.history[channelId]?.find((x) => x.id === messageId);
    if (!m || m.error) throw new Error('The message you’re replying to isn’t available.');
    return { id: m.id, userId: m.senderUserId, text: excerpt(m.text) };
  }

  private dmReplyRef(peerUserId: string, messageId: string): ReplyRef {
    const m = this.history.conversations[peerUserId]?.messages.find((x) => x.id === messageId);
    if (!m || m.error) throw new Error('The message you’re replying to isn’t available.');
    return { id: m.id, userId: m.from === 'me' ? this.api.userId : peerUserId, text: excerpt(m.text) };
  }

  /** Sends through the server, or over the local network when it's down. Returns a note for the latter. */
  private async deliverChannel(payload: ChannelPayload): Promise<string | undefined> {
    try {
      await this.sendChannelOnline(payload);
      return undefined;
    } catch (err) {
      if (!(err instanceof UnreachableError)) throw err;
      await this.sendChannelLan(payload);
      return LAN_NOTE;
    }
  }

  private async deliverDm(payload: DirectPayload): Promise<string | undefined> {
    try {
      await this.sendDmOnline(payload);
      return undefined;
    } catch (err) {
      if (!(err instanceof UnreachableError)) throw err;
      await this.sendDmLan(payload);
      return LAN_NOTE;
    }
  }

  private async sendChannelOnline(payload: ChannelPayload) {
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
  private async sendChannelLan(payload: ChannelPayload) {
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
    for (let i = 0; i < messages.length; i += 200) {
      await this.api.request('POST', `/v1/spaces/${spaceId}/sender-keys`, { messages: messages.slice(i, i + 200) }, () => null);
    }
    out.sentTo.push(...need.map((d) => d.deviceId));
    await this.vault.write('channels', this.channels);
  }

  private store(peerUserId: string, peerUsername: string, msg: StoredDm) {
    const c = (this.history.conversations[peerUserId] ??= { peerUsername, messages: [] });
    c.peerUsername = peerUsername;
    if (c.messages.some((m) => m.id === msg.id)) return;
    c.messages.push(msg);
    this.history.pendingReactions = claimPending(this.history.pendingReactions, peerUserId, msg);
    c.messages.sort((a, b) => a.sentAt.localeCompare(b.sentAt));
  }

  /** Encrypts a DM separately for each of the recipient's devices and each of our other devices. */
  async send(peerUserId: string, peerUsername: string, text: string, opts: SendOptions = {}): Promise<Conversation> {
    const replyTo = opts.replyTo ? this.dmReplyRef(peerUserId, opts.replyTo) : undefined;
    const payload: DirectMessagePayload = {
      v: 1,
      kind: 'dm',
      id: randomUUID(),
      peerUserId,
      peerUsername,
      sentAt: new Date().toISOString(),
      text: DirectMessagePayload.shape.text.parse(text.trim()),
      ...(this.accessKey ? { accessKey: this.accessKey } : {}),
      ...(replyTo ? { replyTo } : {}),
      ...(opts.forwarded ? { forwarded: true as const } : {}),
    };
    const note = await this.deliverDm(payload);
    this.store(peerUserId, peerUsername, {
      id: payload.id,
      from: 'me',
      text: payload.text,
      sentAt: payload.sentAt,
      ...(replyTo ? { reply: replyTo } : {}),
      ...(opts.forwarded ? { forwarded: true } : {}),
      ...(note ? { note } : {}),
    });
    await this.vault.write('messages', this.history);
    return this.conversation(peerUserId);
  }

  /** Adds or takes back our reaction to a message in a DM. It goes to both of us like a message does. */
  async reactInDmMessage(peerUserId: string, peerUsername: string, messageId: string, emoji: string, on: boolean): Promise<Conversation> {
    const target = this.history.conversations[peerUserId]?.messages.find((m) => m.id === messageId);
    if (!target || target.error) throw new Error('You can’t react to that message.');
    const payload: DirectReactionPayload = {
      v: 1,
      kind: 'dmReaction',
      id: randomUUID(),
      peerUserId,
      peerUsername,
      messageId,
      emoji: Emoji.parse(emoji),
      on,
      sentAt: new Date().toISOString(),
      ...(this.accessKey ? { accessKey: this.accessKey } : {}),
    };
    await this.deliverDm(payload);
    applyReaction(target, { userId: this.api.userId, username: 'You', emoji: payload.emoji, at: payload.sentAt, on });
    await this.vault.write('messages', this.history);
    return this.conversation(peerUserId);
  }

  private async sendDmOnline(payload: DirectPayload) {
    const { peerUserId, peerUsername } = payload;
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const key = this.sealed.peers[peerUserId];
    if (key && this.api.sealedSenderRoot()) {
      try {
        if (await this.sendSealed(peerUserId, key, plaintext)) {
          await this.copyToOwnDevices(plaintext);
          return;
        }
      } catch (err) {
        // Anything but being offline: try the normal way below.
        if (err instanceof UnreachableError) throw err;
      }
    }
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

  /**
   * Sends sealed: without signing in, on a connection of its own. Their device list
   * comes from the directory we refresh in the background, so nothing signed in is
   * asked for right before the send, except keys for a device we've never written to.
   * Returns false if they've replaced their access key, so we should send normally.
   */
  private async sendSealed(peerUserId: string, key: string, plaintext: Uint8Array): Promise<boolean> {
    let devices = this.knownDevices(peerUserId);
    if (!devices.length) devices = (await this.api.request('GET', `/v1/users/${peerUserId}/devices`, undefined, (v) => DeviceList.parse(v))).devices;
    const certificate = await this.certificate();
    for (let attempt = 0; ; attempt++) {
      const messages = await this.signal.sealedEncrypt(plaintext, await this.targetsFor(peerUserId, devices), certificate);
      try {
        await this.api.anonymous(`/v1/sealed/${peerUserId}/messages`, { messages }, { [ACCESS_KEY_HEADER]: key }, () => null);
        return true;
      } catch (err) {
        if (err instanceof HttpStatusError && err.status === 401) {
          delete this.sealed.peers[peerUserId];
          await this.vault.write('sealed', this.sealed);
          return false;
        }
        const mismatch = err instanceof HttpStatusError && err.status === 409 ? SealedMismatch.safeParse(err.body) : undefined;
        if (mismatch?.success && attempt === 0) {
          devices = mismatch.data.devices;
          continue;
        }
        throw err;
      }
    }
  }

  /** Someone's devices as of the last directory refresh, leaving out this one. */
  private knownDevices(userId: string): { deviceId: string; signalDeviceId: number }[] {
    return Object.values(this.directory.devices)
      .filter((d) => d.userId === userId && d.deviceId !== this.api.deviceId)
      .map((d) => ({ deviceId: d.deviceId, signalDeviceId: d.signalDeviceId }));
  }

  /**
   * A sealed send carries no copies for our other devices, so they get theirs
   * separately. That send is signed in, so the server sees that we wrote something
   * (not to whom); see docs/sealed-sender.md.
   */
  private async copyToOwnDevices(plaintext: Uint8Array) {
    // Our devices are in the directory too, as members of our servers.
    const known = this.knownDevices(this.api.userId);
    for (let attempt = 0; ; attempt++) {
      const targets = await this.targetsFor(this.api.userId, attempt === 0 && known.length ? known : undefined);
      if (!targets.length) return;
      const messages = await this.signal.encrypt(plaintext, targets);
      try {
        await this.api.request('POST', '/v1/messages', { recipientUserId: this.api.userId, messages }, () => null);
        return;
      } catch (err) {
        if (err instanceof HttpStatusError && err.status === 409 && MismatchedDevices.safeParse(err.body).success && attempt === 0) continue;
        throw err;
      }
    }
  }

  /** Sends a DM straight to the recipient's devices, and our own, that are linked on the local network. */
  private async sendDmLan(payload: DirectPayload) {
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
