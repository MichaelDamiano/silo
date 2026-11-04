import crypto from 'node:crypto';
import dgram from 'node:dgram';
import net from 'node:net';
import {
  LanBeacon,
  LanFrame,
  LanHello,
  LanProof,
  fromBase64Url,
  lanLinkPayload,
  toBase64Url,
  verify,
} from '@silo/protocol';

/** A device we already know from the server, which may show up on the local network. */
export interface PeerDevice {
  userId: string;
  username: string;
  deviceId: string;
  signalDeviceId: number;
  /** The device's Ed25519 login key. Only devices we know this for can link with us. */
  publicKey: string;
}

export interface LanOptions {
  deviceId: string;
  /** Signs with this device's Ed25519 login key. */
  sign(payload: Uint8Array): string;
  /** Looks up a device we know from the server. Unknown devices are refused. */
  lookup(deviceId: string): PeerDevice | undefined;
  onFrame(peer: PeerDevice, frame: LanFrame): void;
  onPeersChanged(): void;
  /** Overridable for tests. Defaults to a site-local multicast group. */
  beaconAddress?: string;
  beaconPort?: number;
  beaconIntervalMs?: number;
}

const BEACON_ADDRESS = '239.255.77.77';
const BEACON_PORT = 47821;
const MAX_FRAME = 200 * 1024;
const HANDSHAKE_MS = 10_000;
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

/** Splits a TCP stream into length-prefixed frames. */
class Framer {
  private buf = Buffer.alloc(0);
  constructor(private readonly onFrame: (frame: Buffer) => void, private readonly onError: (err: Error) => void) {}
  push(chunk: Buffer) {
    this.buf = Buffer.concat([this.buf, chunk]);
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32BE(0);
      if (len > MAX_FRAME) return this.onError(new Error('frame too large'));
      if (this.buf.length < 4 + len) return;
      const frame = this.buf.subarray(4, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      this.onFrame(frame);
    }
  }
}

function writeFrame(socket: net.Socket, data: Buffer) {
  const head = Buffer.alloc(4);
  head.writeUInt32BE(data.length);
  socket.write(Buffer.concat([head, data]));
}

/**
 * One authenticated, encrypted link to another device. Both sides send a fresh
 * X25519 key, then sign both keys and both device ids with their login key. The
 * shared secret from the key exchange encrypts everything after that with
 * AES-256-GCM, a separate key and counter in each direction.
 */
class Link {
  peer?: PeerDevice;
  private sendKey?: Buffer;
  private recvKey?: Buffer;
  private sendCounter = 0n;
  private recvCounter = 0n;
  private readonly eph = crypto.generateKeyPairSync('x25519');
  private readonly ephRaw = (this.eph.publicKey.export({ type: 'spki', format: 'der' }) as Buffer).subarray(12);
  private peerHello?: LanHello;
  private closed = false;

  constructor(
    private readonly socket: net.Socket,
    private readonly initiator: boolean,
    private readonly opts: LanOptions,
    private readonly onReady: (link: Link) => void,
    private readonly onClose: (link: Link) => void,
  ) {
    const timer = setTimeout(() => this.close(), HANDSHAKE_MS);
    const framer = new Framer(
      (f) => {
        try {
          this.handle(f);
          if (this.peer) clearTimeout(timer);
        } catch {
          this.close();
        }
      },
      () => this.close(),
    );
    socket.on('data', (c) => framer.push(c));
    socket.on('error', () => this.close());
    socket.on('close', () => this.close());
    socket.setNoDelay(true);
    writeFrame(socket, Buffer.from(JSON.stringify({ v: 1, deviceId: opts.deviceId, ephemeral: toBase64Url(this.ephRaw) } satisfies LanHello)));
  }

  private transcript(hello: LanHello) {
    const mine = toBase64Url(this.ephRaw);
    return this.initiator
      ? lanLinkPayload(mine, hello.ephemeral, this.opts.deviceId, hello.deviceId)
      : lanLinkPayload(hello.ephemeral, mine, hello.deviceId, this.opts.deviceId);
  }

  private handle(frame: Buffer) {
    if (!this.peerHello) {
      const hello = LanHello.parse(JSON.parse(frame.toString('utf8')));
      if (hello.deviceId === this.opts.deviceId) throw new Error('that is us');
      this.peerHello = hello;
      writeFrame(this.socket, Buffer.from(JSON.stringify({ signature: this.opts.sign(this.transcript(hello)) })));
      return;
    }
    if (!this.peer) {
      const { signature } = LanProof.parse(JSON.parse(frame.toString('utf8')));
      const hello = this.peerHello;
      const known = this.opts.lookup(hello.deviceId);
      if (!known || !verify(signature, this.transcript(hello), known.publicKey)) throw new Error('unknown or unverified device');
      const peerKey = crypto.createPublicKey({
        key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(fromBase64Url(hello.ephemeral))]),
        format: 'der',
        type: 'spki',
      });
      const shared = crypto.diffieHellman({ privateKey: this.eph.privateKey, publicKey: peerKey });
      const keys = Buffer.from(crypto.hkdfSync('sha256', shared, Buffer.from(this.transcript(hello)), 'silo lan link v1', 64));
      const [i2r, r2i] = [keys.subarray(0, 32), keys.subarray(32)];
      this.sendKey = this.initiator ? i2r : r2i;
      this.recvKey = this.initiator ? r2i : i2r;
      this.peer = known;
      this.onReady(this);
      return;
    }
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(this.recvCounter++);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.recvKey!, nonce);
    decipher.setAuthTag(frame.subarray(frame.length - 16));
    const plain = Buffer.concat([decipher.update(frame.subarray(0, frame.length - 16)), decipher.final()]);
    this.opts.onFrame(this.peer, LanFrame.parse(JSON.parse(plain.toString('utf8'))));
  }

  send(frame: LanFrame) {
    if (!this.sendKey || this.closed) return false;
    const nonce = Buffer.alloc(12);
    nonce.writeBigUInt64BE(this.sendCounter++);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.sendKey, nonce);
    const body = Buffer.concat([cipher.update(JSON.stringify(frame), 'utf8'), cipher.final(), cipher.getAuthTag()]);
    writeFrame(this.socket, body);
    return true;
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.socket.destroy();
    this.onClose(this);
  }
}

/**
 * Finds other Silo devices on the local network and keeps encrypted links to the
 * ones we already know from the server. Messages sent over these links are the
 * same end-to-end encrypted messages the server would carry.
 */
export class LanNode {
  private readonly id = toBase64Url(crypto.randomBytes(16));
  private server?: net.Server;
  private udp?: dgram.Socket;
  private beaconTimer?: NodeJS.Timeout;
  private readonly links = new Map<string, Link>();
  private readonly dialing = new Set<string>();
  private port = 0;

  constructor(private readonly opts: LanOptions) {}

  async start() {
    this.server = net.createServer((socket) => this.adopt(socket, false));
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject);
      this.server!.listen(0, () => resolve());
    });
    this.port = (this.server.address() as net.AddressInfo).port;

    const udp = (this.udp = dgram.createSocket({ type: 'udp4', reuseAddr: true }));
    const address = this.opts.beaconAddress ?? BEACON_ADDRESS;
    const port = this.opts.beaconPort ?? BEACON_PORT;
    udp.on('message', (msg, rinfo) => this.onBeacon(msg, rinfo.address));
    udp.on('error', () => undefined);
    await new Promise<void>((resolve) => udp.bind(port, () => resolve()));
    try {
      if (address.startsWith('239.')) {
        udp.addMembership(address);
        udp.setMulticastLoopback(true);
      } else udp.setBroadcast(true);
    } catch {
      // No multicast-capable network right now; we'll still answer devices that reach us.
    }
    const beacon = Buffer.from(JSON.stringify({ silo: 1, id: this.id, port: this.port } satisfies LanBeacon));
    const send = () => udp.send(beacon, port, address, () => undefined);
    send();
    this.beaconTimer = setInterval(send, this.opts.beaconIntervalMs ?? 5000);
  }

  stop() {
    clearInterval(this.beaconTimer);
    this.udp?.close();
    this.server?.close();
    for (const link of [...this.links.values()]) link.close();
    this.links.clear();
  }

  /** Devices with a working link right now. */
  peers(): PeerDevice[] {
    return [...this.links.values()].map((l) => l.peer!).filter(Boolean);
  }

  isConnected(deviceId: string) {
    return this.links.has(deviceId);
  }

  send(deviceId: string, frame: LanFrame): boolean {
    return this.links.get(deviceId)?.send(frame) ?? false;
  }

  private onBeacon(msg: Buffer, from: string) {
    let b: LanBeacon;
    try {
      b = LanBeacon.parse(JSON.parse(msg.toString('utf8')));
    } catch {
      return;
    }
    // Only one side dials, so two devices don't open two links to each other.
    if (b.id === this.id || b.id < this.id || this.dialing.has(b.id)) return;
    this.dialing.add(b.id);
    const socket = net.connect({ host: from, port: b.port, timeout: HANDSHAKE_MS });
    socket.once('connect', () => socket.setTimeout(0));
    socket.once('timeout', () => socket.destroy());
    socket.once('close', () => this.dialing.delete(b.id));
    this.adopt(socket, true);
  }

  private adopt(socket: net.Socket, initiator: boolean) {
    new Link(
      socket,
      initiator,
      this.opts,
      (link) => {
        const id = link.peer!.deviceId;
        const old = this.links.get(id);
        this.links.set(id, link);
        old?.close();
        this.opts.onPeersChanged();
      },
      (link) => {
        if (link.peer && this.links.get(link.peer.deviceId) === link) {
          this.links.delete(link.peer.deviceId);
          this.opts.onPeersChanged();
        }
      },
    );
  }
}
