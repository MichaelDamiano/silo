import { describe, expect, it } from 'vitest';
import { generateDeviceKeyPair, sign, toBase64Url, type DeviceBundle } from '@silo/protocol';
import { randomUUID } from 'node:crypto';
import { IdentityChangedError, MemoryStateStore, MissingSenderKeyError, SignalDevice } from './index.js';

const text = (s: string) => new TextEncoder().encode(s);
const read = (b: Uint8Array) => new TextDecoder().decode(b);

/** A stand-in for the server: turns an upload into the bundle another device would fetch. */
async function makeDevice(userId: string, signalDeviceId: number, store = new MemoryStateStore()) {
  const login = generateDeviceKeyPair();
  const deviceId = randomUUID();
  const dev = await SignalDevice.open(store);
  dev.setAddress(userId, signalDeviceId);
  const upload = await dev.keyUpload(deviceId, (p) => sign(p, login.secretKey));
  const preKeys = [...upload.oneTimePreKeys];
  const bundle = (): DeviceBundle => ({
    deviceId,
    signalDeviceId,
    registrationId: upload.registrationId,
    devicePublicKey: toBase64Url(login.publicKey),
    identityKey: upload.identityKey,
    identitySignature: upload.identitySignature,
    signedPreKey: upload.signedPreKey,
    kyberPreKey: upload.kyberPreKey,
    oneTimePreKey: preKeys.shift() ?? null,
  });
  return { dev, deviceId, userId, signalDeviceId, bundle, store };
}

describe('SignalDevice', () => {
  it('sets up a session from a bundle and exchanges messages both ways', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);

    const [first] = await alice.dev.encrypt(text('hi bob'), [{ ...bob, bundle: bob.bundle() }]);
    expect(first!.type).toBe(3);
    const got = await bob.dev.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, type: first!.type, body: first!.body });
    expect(read(got)).toBe('hi bob');

    const [reply] = await bob.dev.encrypt(text('hi alice'), [alice]);
    expect(reply!.type).toBe(2);
    expect(read(await alice.dev.decrypt({ senderUserId: 'bob-id', senderSignalDeviceId: 1, ...reply! }))).toBe('hi alice');
  });

  it('uses up the one-time pre-key that started the session', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);
    const before = bob.dev.preKeyCount;
    const [m] = await alice.dev.encrypt(text('x'), [{ ...bob, bundle: bob.bundle() }]);
    await bob.dev.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, ...m! });
    expect(bob.dev.preKeyCount).toBe(before - 1);
  });

  it('still works when no one-time pre-key is left', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);
    const [m] = await alice.dev.encrypt(text('no otk'), [{ ...bob, bundle: { ...bob.bundle(), oneTimePreKey: null } }]);
    expect(read(await bob.dev.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, ...m! }))).toBe('no otk');
  });

  it('survives a restart by reloading its saved state', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);
    const [m] = await alice.dev.encrypt(text('one'), [{ ...bob, bundle: bob.bundle() }]);
    await bob.dev.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, ...m! });

    const bob2 = await SignalDevice.open(bob.store);
    bob2.setAddress('bob-id', 1);
    const [m2] = await alice.dev.encrypt(text('two'), [bob]);
    expect(read(await bob2.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, ...m2! }))).toBe('two');
  });

  it('refuses a bundle whose identity was not signed by the device key', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);
    const forged = { ...bob.bundle(), devicePublicKey: toBase64Url(generateDeviceKeyPair().publicKey) };
    await expect(alice.dev.encrypt(text('x'), [{ ...bob, bundle: forged }])).rejects.toThrow(/identity signature/);
  });

  it('blocks messages when a known device suddenly has a different identity', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);
    const [m] = await alice.dev.encrypt(text('x'), [{ ...bob, bundle: bob.bundle() }]);
    await bob.dev.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, ...m! });

    // Someone else claims to be alice's device 1 with a new identity key.
    const impostor = await makeDevice('alice-id', 1);
    const [fake] = await impostor.dev.encrypt(text('trust me'), [{ ...bob, bundle: bob.bundle() }]);
    await expect(bob.dev.decrypt({ senderUserId: 'alice-id', senderSignalDeviceId: 1, ...fake! })).rejects.toBeInstanceOf(
      IdentityChangedError,
    );
  });

  it('can never decrypt a message twice (replay)', async () => {
    const alice = await makeDevice('alice-id', 1);
    const bob = await makeDevice('bob-id', 1);
    const [m] = await alice.dev.encrypt(text('once'), [{ ...bob, bundle: bob.bundle() }]);
    const env = { senderUserId: 'alice-id', senderSignalDeviceId: 1, ...m! };
    await bob.dev.decrypt(env);
    await expect(bob.dev.decrypt(env)).rejects.toThrow();
  });

  describe('sender keys', () => {
    it('lets every holder of the key read a channel message encrypted once', async () => {
      const alice = await makeDevice('alice-id', 1);
      const bob = await makeDevice('bob-id', 1);
      const carol = await makeDevice('carol-id', 2);
      const dist = randomUUID();
      const skdm = await alice.dev.senderKeyDistribution(dist);
      await bob.dev.processSenderKeyDistribution('alice-id', 1, skdm);
      await carol.dev.processSenderKeyDistribution('alice-id', 1, skdm);

      const body = await alice.dev.groupEncrypt(dist, text('hello channel'));
      for (const d of [bob, carol]) {
        const out = await d.dev.groupDecrypt('alice-id', 1, body);
        expect(out.distributionId).toBe(dist);
        expect(read(out.plaintext)).toBe('hello channel');
      }
    });

    it('reports a missing key rather than failing, so the message can be retried', async () => {
      const alice = await makeDevice('alice-id', 1);
      const bob = await makeDevice('bob-id', 1);
      const body = await alice.dev.groupEncrypt(randomUUID(), text('too early'));
      await expect(bob.dev.groupDecrypt('alice-id', 1, body)).rejects.toBeInstanceOf(MissingSenderKeyError);
    });

    it('rejects a message that claims to be from someone other than its signer', async () => {
      const alice = await makeDevice('alice-id', 1);
      const mallory = await makeDevice('mallory-id', 1);
      const bob = await makeDevice('bob-id', 1);
      const dist = randomUUID();
      await bob.dev.processSenderKeyDistribution('alice-id', 1, await alice.dev.senderKeyDistribution(dist));
      // Mallory uses the same distribution id with her own key and the server labels it as Alice's.
      await mallory.dev.senderKeyDistribution(dist);
      const forged = await mallory.dev.groupEncrypt(dist, text('send me your recovery key'));
      await expect(bob.dev.groupDecrypt('alice-id', 1, forged)).rejects.toThrow();
    });

    it('keeps sender keys across a restart', async () => {
      const alice = await makeDevice('alice-id', 1);
      const bob = await makeDevice('bob-id', 1);
      const dist = randomUUID();
      await bob.dev.processSenderKeyDistribution('alice-id', 1, await alice.dev.senderKeyDistribution(dist));
      const reopened = await SignalDevice.open(bob.store);
      reopened.setAddress('bob-id', 1);
      const body = await alice.dev.groupEncrypt(dist, text('after restart'));
      expect(read((await reopened.groupDecrypt('alice-id', 1, body)).plaintext)).toBe('after restart');
    });

    it('cannot read messages sent before it received the key, or under a rotated key', async () => {
      const alice = await makeDevice('alice-id', 1);
      const bob = await makeDevice('bob-id', 1);
      const dist = randomUUID();
      const old = await alice.dev.groupEncrypt(dist, text('before bob joined'));
      await bob.dev.processSenderKeyDistribution('alice-id', 1, await alice.dev.senderKeyDistribution(dist));
      await expect(bob.dev.groupDecrypt('alice-id', 1, old)).rejects.toThrow();
      const rotated = await alice.dev.groupEncrypt(randomUUID(), text('after bob was removed'));
      await expect(bob.dev.groupDecrypt('alice-id', 1, rotated)).rejects.toBeInstanceOf(MissingSenderKeyError);
    });
  });
});
