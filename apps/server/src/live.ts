import type { FastifyInstance } from 'fastify';
import websocket from '@fastify/websocket';
import type { WebSocket } from 'ws';
import type { Db } from './db.js';
import { hashSecret } from './secrets.js';

/**
 * Live delivery. A device keeps one WebSocket open and gets a short nudge when
 * envelopes arrive; it then fetches them over HTTPS. Nothing secret is sent here.
 */
export class LiveHub {
  private sockets = new Map<string, Set<WebSocket>>();

  add(deviceId: string, ws: WebSocket) {
    let set = this.sockets.get(deviceId);
    if (!set) this.sockets.set(deviceId, (set = new Set()));
    set.add(ws);
    ws.on('close', () => {
      set!.delete(ws);
      if (set!.size === 0) this.sockets.delete(deviceId);
    });
  }

  /** Nudges devices to fetch: 'envelopes' for pairwise messages, 'channel' for channel messages. */
  notify(deviceIds: Iterable<string>, type: 'envelopes' | 'channel' = 'envelopes') {
    for (const id of deviceIds) for (const ws of this.sockets.get(id) ?? []) ws.send(JSON.stringify({ type }));
  }

  /** Called when a device is revoked so it stops receiving nudges at once. */
  disconnect(deviceIds: Iterable<string>) {
    for (const id of deviceIds) for (const ws of this.sockets.get(id) ?? []) ws.close(4001, 'revoked');
  }

  closeAll() {
    for (const set of this.sockets.values()) for (const ws of set) ws.close(1001, 'server shutting down');
  }
}

declare module 'fastify' {
  interface FastifyInstance {
    live: LiveHub;
  }
}

export async function liveRoutes(app: FastifyInstance, opts: { db: Db }) {
  await app.register(websocket, { options: { maxPayload: 4096 } });
  app.get('/v1/live', { websocket: true }, (socket) => {
    // The token is sent as the first message rather than in the URL, so it never lands in logs.
    const timeout = setTimeout(() => socket.close(4000, 'auth timeout'), 5000);
    socket.once('message', async (raw) => {
      clearTimeout(timeout);
      try {
        const { token } = JSON.parse(raw.toString()) as { token?: unknown };
        if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('bad token');
        const { rows } = await opts.db.query<{ device_id: string }>(
          `SELECT s.device_id FROM sessions s JOIN devices d ON d.id = s.device_id
            WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND d.revoked_at IS NULL`,
          [hashSecret(token)],
        );
        if (!rows[0]) throw new Error('unknown session');
        app.live.add(rows[0].device_id, socket);
        socket.send(JSON.stringify({ type: 'ready' }));
        // Tell the device to check for anything that arrived while it was offline.
        socket.send(JSON.stringify({ type: 'envelopes' }));
      } catch {
        socket.close(4001, 'authentication failed');
      }
    });
    const ping = setInterval(() => socket.ping(), 25_000);
    socket.on('close', () => clearInterval(ping));
  });
}
