import tls from 'node:tls';
import { SocksClient } from 'socks';
import { Agent, WebSocket, fetch, type Dispatcher } from 'undici';
import { isOnion } from '@silo/protocol';

export interface TorSettings {
  /** The Tor SOCKS proxy: 9050 for the Tor service, 9150 for Tor Browser. */
  proxyHost: string;
  proxyPort: number;
  /** Send every connection through Tor, not just onion addresses, to hide this device's IP from the server. */
  always: boolean;
}

export const DEFAULT_TOR: TorSettings = { proxyHost: '127.0.0.1', proxyPort: 9050, always: false };

/** Errors that happen before a request reaches the server, so retrying elsewhere can't send it twice. */
const CONNECT_ERRORS = new Set([
  'ECONNREFUSED',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'ENETUNREACH',
  'EHOSTUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET',
]);

function causeCode(err: unknown): string | undefined {
  let e = err as { code?: string; cause?: unknown; name?: string } | undefined;
  for (let i = 0; e && i < 5; i++) {
    if (e.name === 'SocksClientError') return 'SOCKS';
    if (typeof e.code === 'string') return e.code;
    e = e.cause as typeof e;
  }
  return undefined;
}

function beforeServer(err: unknown): boolean {
  const code = causeCode(err);
  return !!code && (CONNECT_ERRORS.has(code) || code === 'SOCKS' || code.startsWith('ERR_TLS') || /CERT|UNABLE_TO|SELF_SIGNED/.test(code));
}

/** Thrown when no address for the server could be reached. */
export class UnreachableError extends Error {
  constructor(tried: string[], last: unknown) {
    super(`Couldn't reach the server at ${tried.join(', ')}: ${(last as Error)?.message ?? 'unknown error'}`);
  }
}

/** A connection agent that tunnels through a SOCKS5 proxy, letting Tor resolve the hostname. */
function socksAgent(tor: TorSettings): Agent {
  return new Agent({
    connect: (opts, callback) => {
      const port = Number(opts.port) || (opts.protocol === 'https:' ? 443 : 80);
      SocksClient.createConnection({
        proxy: { host: tor.proxyHost, port: tor.proxyPort, type: 5 },
        command: 'connect',
        destination: { host: opts.hostname, port },
        timeout: 60_000,
      }).then(
        ({ socket }) => {
          if (opts.protocol !== 'https:') return callback(null, socket);
          const secure = tls.connect({ socket, servername: opts.servername || opts.hostname, ALPNProtocols: ['http/1.1'] });
          secure.once('secureConnect', () => callback(null, secure));
          secure.once('error', (e) => callback(e, null));
        },
        (err: Error) => callback(err, null),
      );
    },
  });
}

/**
 * Talks to one Silo server over whichever of its addresses works. It tries the
 * current address first and moves on to the next when a connection can't be
 * made, then sticks with the one that worked. Onion addresses, or every
 * address when asked, go through Tor.
 */
export class Transport {
  private list: string[];
  private index = 0;
  private readonly direct = new Agent({ connect: { timeout: 10_000 } });
  private tor?: Agent;

  constructor(
    endpoints: string[],
    private torSettings: TorSettings,
    private readonly onSwitch: (endpoint: string, viaTor: boolean) => void = () => undefined,
  ) {
    this.list = [...new Set(endpoints)];
    if (!this.list.length) throw new Error('no server address');
  }

  get current(): string {
    return this.list[this.index]!;
  }

  get endpoints(): readonly string[] {
    return this.list;
  }

  viaTor(endpoint = this.current): boolean {
    return this.torSettings.always || isOnion(new URL(endpoint).hostname);
  }

  /** Replaces the address list, keeping the current address in front if it's still listed. */
  setEndpoints(endpoints: string[]) {
    const current = this.current;
    const next = [...new Set(endpoints)];
    if (!next.length) return;
    this.list = next.includes(current) ? [current, ...next.filter((e) => e !== current)] : next;
    this.index = 0;
  }

  setTor(settings: TorSettings) {
    this.torSettings = settings;
    void this.tor?.close();
    this.tor = undefined;
  }

  private dispatcher(endpoint: string): Dispatcher {
    if (!this.viaTor(endpoint)) return this.direct;
    return (this.tor ??= socksAgent(this.torSettings));
  }

  /**
   * Sends a request, failing over to the next address if it can't connect. A
   * request that might have reached the server (say the connection dropped
   * mid-way) is only retried elsewhere if it is safe to repeat.
   */
  async request(path: string, init: { method?: string; headers?: Record<string, string>; body?: string }): Promise<Response> {
    const method = init.method ?? 'GET';
    const tried: string[] = [];
    let last: unknown;
    for (let n = 0; n < this.list.length; n++) {
      const i = (this.index + n) % this.list.length;
      const endpoint = this.list[i]!;
      tried.push(endpoint);
      try {
        const res = await fetch(endpoint + path, {
          ...init,
          method,
          redirect: 'error',
          dispatcher: this.dispatcher(endpoint),
          signal: AbortSignal.timeout(this.viaTor(endpoint) ? 90_000 : 30_000),
        });
        if (i !== this.index) {
          this.index = i;
          this.onSwitch(endpoint, this.viaTor(endpoint));
        }
        return res as unknown as Response;
      } catch (err) {
        last = err;
        if (!(method === 'GET' || beforeServer(err))) throw err;
      }
    }
    throw new UnreachableError(tried, last);
  }

  /** Opens the live WebSocket on the current address, through Tor when needed. */
  socket(path: string): WebSocket {
    const url = this.current.replace(/^http/, 'ws') + path;
    return new WebSocket(url, { dispatcher: this.dispatcher(this.current) });
  }

  close() {
    void this.direct.close();
    void this.tor?.close();
  }
}
