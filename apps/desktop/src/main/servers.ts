import { randomBytes } from 'node:crypto';
import { Endpoint, ServerInfo, SignedServerInfo, serverInfoPayload, toBase64Url, verify } from '@silo/protocol';
import { DEFAULT_TOR, Transport, type TorSettings } from './transport.js';
import type { Vault } from './vault.js';

export interface KnownServer {
  /** The server's identity key, pinned the first time we talked to it. */
  serverKey: string;
  /** Addresses the server itself published, in its order. */
  endpoints: string[];
  /** Addresses added by hand, for example an onion address a friend sent. */
  added: string[];
  issuedAt: string;
  /** The key sender certificates chain to, from the same signed answer as the addresses. */
  sealedSenderRoot?: string;
}

interface Saved {
  servers: KnownServer[];
  tor: TorSettings;
  /** Whether to look for other Silo devices on the local network. Off unless turned on. */
  lan: boolean;
}

export class ServerIdentityError extends Error {}

/** Plain http is only allowed to this machine and to onion services. */
export function normalizeServerUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error('That isn’t a valid server address.');
  }
  if (url.username || url.password) throw new Error('The server address must not contain a username or password.');
  const parsed = Endpoint.safeParse(url.origin);
  if (!parsed.success) throw new Error('The server address must use https:// (http:// is only allowed for localhost and .onion addresses).');
  return parsed.data;
}

/**
 * Remembers each server's identity key and addresses. A server's address list is
 * only accepted when it is signed by the key we pinned, so nobody in between can
 * steer this device to an address the server didn't publish.
 */
export class ServerDirectory {
  private saved: Saved = { servers: [], tor: DEFAULT_TOR, lan: false };

  private constructor(private readonly vault?: Vault) {}

  static async open(vault?: Vault): Promise<ServerDirectory> {
    const d = new ServerDirectory(vault);
    const saved = await vault?.read<Saved>('servers');
    if (saved) d.saved = { servers: saved.servers ?? [], tor: { ...DEFAULT_TOR, ...saved.tor }, lan: saved.lan === true };
    return d;
  }

  get tor(): TorSettings {
    return this.saved.tor;
  }

  get lan(): boolean {
    return this.saved.lan;
  }

  async setLan(enabled: boolean) {
    this.saved.lan = enabled;
    await this.save();
  }

  async setTor(tor: TorSettings) {
    this.saved.tor = tor;
    await this.save();
  }

  find(endpoint: string): KnownServer | undefined {
    return this.saved.servers.find((s) => s.endpoints.includes(endpoint) || s.added.includes(endpoint));
  }

  byKey(serverKey: string): KnownServer | undefined {
    return this.saved.servers.find((s) => s.serverKey === serverKey);
  }

  /** Every address worth trying for this server: the one we're using, then the published ones, then hand-added ones. */
  addressesFor(s: KnownServer, first?: string): string[] {
    return [...new Set([...(first ? [first] : []), ...s.endpoints, ...s.added])];
  }

  /**
   * Connects to the server behind an address. The server must prove it holds the
   * identity key we pinned before; a new server's key is pinned now.
   */
  async connect(address: string, onSwitch?: (endpoint: string, viaTor: boolean) => void): Promise<{ transport: Transport; server: KnownServer }> {
    const base = normalizeServerUrl(address);
    const known = this.find(base);
    const transport = new Transport(known ? this.addressesFor(known, base) : [base], this.tor, onSwitch);
    try {
      const info = await this.fetchInfo(transport);
      const server = await this.accept(info, known);
      // Remember the address that was typed in too, so a different server answering there later is caught.
      if (!server.endpoints.includes(base) && !server.added.includes(base)) {
        server.added.push(base);
        await this.save();
      }
      transport.setEndpoints(this.addressesFor(server, transport.current));
      return { transport, server };
    } catch (err) {
      transport.close();
      throw err;
    }
  }

  /** Re-reads the signed address list, for example after signing in, and updates what we try. */
  async refresh(transport: Transport, serverKey: string): Promise<KnownServer> {
    const server = await this.accept(await this.fetchInfo(transport), this.byKey(serverKey));
    transport.setEndpoints(this.addressesFor(server, transport.current));
    return server;
  }

  /** Adds an address by hand after checking that the same server, with the same key, answers there. */
  async addAddress(serverKey: string, address: string): Promise<KnownServer> {
    const known = this.byKey(serverKey);
    if (!known) throw new Error('Unknown server.');
    const base = normalizeServerUrl(address);
    const probe = new Transport([base], this.tor);
    try {
      const info = await this.fetchInfo(probe);
      if (info.serverKey !== serverKey) throw new ServerIdentityError(`${base} is a different server, so it wasn't added.`);
      const server = await this.accept(info, known);
      if (!server.endpoints.includes(base) && !server.added.includes(base)) server.added.push(base);
      await this.save();
      return server;
    } finally {
      probe.close();
    }
  }

  async removeAddress(serverKey: string, address: string): Promise<KnownServer> {
    const known = this.byKey(serverKey);
    if (!known) throw new Error('Unknown server.');
    known.added = known.added.filter((a) => a !== address);
    await this.save();
    return known;
  }

  private async fetchInfo(transport: Transport): Promise<ServerInfo> {
    const nonce = toBase64Url(randomBytes(24));
    const res = await transport.request(`/v1/server-info?nonce=${nonce}`, {});
    if (!res.ok) throw new Error(`The server didn't share its identity (${res.status}). Is this a Silo server?`);
    const signed = SignedServerInfo.parse(await res.json());
    const info = ServerInfo.parse(JSON.parse(signed.info));
    if (!verify(signed.signature, serverInfoPayload(signed.info), info.serverKey) || info.nonce !== nonce) {
      throw new ServerIdentityError('The server’s identity proof is invalid.');
    }
    return info;
  }

  private async accept(info: ServerInfo, known: KnownServer | undefined): Promise<KnownServer> {
    if (known && known.serverKey !== info.serverKey) {
      throw new ServerIdentityError(
        'This address answered as a different server than before, so Silo refused to connect. Someone may be intercepting the connection.',
      );
    }
    const existing = known ?? this.byKey(info.serverKey);
    if (existing) {
      // Ignore an older list, so a replayed answer can't roll back the addresses.
      if (info.issuedAt >= existing.issuedAt) {
        existing.endpoints = info.endpoints;
        existing.issuedAt = info.issuedAt;
        if (info.sealedSenderRoot) existing.sealedSenderRoot = info.sealedSenderRoot;
      }
      await this.save();
      return existing;
    }
    const fresh: KnownServer = {
      serverKey: info.serverKey,
      endpoints: info.endpoints,
      added: [],
      issuedAt: info.issuedAt,
      ...(info.sealedSenderRoot ? { sealedSenderRoot: info.sealedSenderRoot } : {}),
    };
    this.saved.servers.push(fresh);
    await this.save();
    return fresh;
  }

  private async save() {
    await this.vault?.write('servers', this.saved);
  }
}
