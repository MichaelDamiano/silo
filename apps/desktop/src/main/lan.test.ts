import { afterEach, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { generateDeviceKeyPair, sign, toBase64Url } from '@silo/protocol';
import type { LanFrame } from '@silo/protocol';
import { LanNode, type PeerDevice } from './lan.js';

const nodes: LanNode[] = [];
afterEach(() => {
  while (nodes.length) nodes.pop()!.stop();
});

let port = 47900;

function device(username: string) {
  const key = generateDeviceKeyPair();
  const info: PeerDevice = { userId: randomUUID(), username, deviceId: randomUUID(), signalDeviceId: 1, publicKey: toBase64Url(key.publicKey) };
  return { key, info };
}

async function node(me: ReturnType<typeof device>, known: PeerDevice[], beaconPort: number) {
  const got: { from: string; frame: LanFrame }[] = [];
  const n = new LanNode({
    deviceId: me.info.deviceId,
    sign: (p) => sign(p, me.key.secretKey),
    lookup: (id) => known.find((k) => k.deviceId === id),
    onFrame: (peer, frame) => got.push({ from: peer.username, frame }),
    onPeersChanged: () => undefined,
    beaconPort,
    beaconIntervalMs: 100,
  });
  await n.start();
  nodes.push(n);
  return { n, got };
}

const until = async (fn: () => boolean, ms = 5000) => {
  const end = Date.now() + ms;
  while (!fn()) {
    if (Date.now() > end) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};

describe('LanNode', () => {
  it('finds a known device, links up, and carries frames both ways', async () => {
    const p = port++;
    const alice = device('alice');
    const bob = device('bob');
    const a = await node(alice, [bob.info], p);
    const b = await node(bob, [alice.info], p);
    await until(() => a.n.isConnected(bob.info.deviceId) && b.n.isConnected(alice.info.deviceId));
    expect(a.n.send(bob.info.deviceId, { t: 'envelope', type: 2, body: 'AAAA' })).toBe(true);
    expect(b.n.send(alice.info.deviceId, { t: 'channel', spaceId: randomUUID(), channelId: randomUUID(), body: 'BBBB' })).toBe(true);
    await until(() => a.got.length === 1 && b.got.length === 1);
    expect(b.got[0]).toMatchObject({ from: 'alice', frame: { t: 'envelope', body: 'AAAA' } });
    expect(a.got[0]!.from).toBe('bob');
  });

  it('refuses devices it does not know from the server', async () => {
    const p = port++;
    const alice = device('alice');
    const stranger = device('mallory');
    const a = await node(alice, [], p);
    const m = await node(stranger, [alice.info], p);
    await new Promise((r) => setTimeout(r, 600));
    expect(a.n.peers()).toHaveLength(0);
    expect(m.n.peers()).toHaveLength(0);
  });

  it('refuses a device that claims a known id but signs with another key', async () => {
    const p = port++;
    const alice = device('alice');
    const bob = device('bob');
    const a = await node(alice, [bob.info], p);
    // Claims to be bob's device, but holds a different key.
    await node({ key: generateDeviceKeyPair(), info: bob.info }, [alice.info], p);
    await new Promise((r) => setTimeout(r, 600));
    expect(a.n.peers()).toHaveLength(0);
  });
});
