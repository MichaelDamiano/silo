import * as S from '@signalapp/libsignal-client';
import { signalIdentityPayload, type DeviceBundle, type UploadKeysRequest } from '@silo/protocol';
import { verify as verifyEd25519 } from '@silo/protocol';

export { formatSafetyNumber, safetyNumber } from './safety.js';
export { issueSenderCertificate, sealedSenderKeys } from './certificates.js';

/**
 * Everything one device needs to run the Signal protocol, kept as plain data so it
 * can be encrypted and written to disk. Record values are libsignal's own
 * serialised form, base64 encoded.
 */
export interface SignalState {
  identityKeyPair: string;
  registrationId: number;
  nextPreKeyId: number;
  preKeys: Record<string, string>;
  signedPreKeys: Record<string, string>;
  kyberPreKeys: Record<string, string>;
  sessions: Record<string, string>;
  /** Identity keys of everyone we've talked to, by address. Trust on first use. */
  identities: Record<string, string>;
  /** Sender keys for group channels, ours and other people's, by address and distribution id. */
  senderKeys?: Record<string, string>;
}

export interface StateStore {
  load(): Promise<SignalState | null>;
  save(state: SignalState): Promise<void>;
}

export class MemoryStateStore implements StateStore {
  state: SignalState | null = null;
  async load() {
    return this.state ? structuredClone(this.state) : null;
  }
  async save(state: SignalState) {
    this.state = structuredClone(state);
  }
}

/** Thrown when a channel message arrives before the sender's key has reached us. */
export class MissingSenderKeyError extends Error {
  constructor() {
    super('The key for this message has not arrived yet.');
  }
}

/** Thrown when someone's encryption identity changed since we last talked to them. */
export class IdentityChangedError extends Error {
  constructor(public readonly userId: string) {
    super('This person’s encryption key has changed. Messages to and from them are blocked until you verify it.');
  }
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64'));
const addrKey = (a: S.ProtocolAddress) => `${a.name()}.${a.deviceId()}`;
const sameBytes = (a: Uint8Array, b: Uint8Array) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;

const SIGNED_PREKEY_ID = 1;
const KYBER_PREKEY_ID = 1;
const PREKEY_BATCH = 100;

export interface Target {
  userId: string;
  deviceId: string;
  signalDeviceId: number;
  /** Needed only when there is no session with this device yet. */
  bundle?: DeviceBundle;
}

/** Envelope type for sealed-sender messages, next to Signal's own 2 (whisper) and 3 (pre-key). */
export const SEALED = 6 as const;

export interface OutgoingCopy {
  deviceId: string;
  type: 2 | 3 | typeof SEALED;
  body: string;
}

/**
 * One device's Signal protocol engine. Operations run one at a time, and the state
 * is saved after each one, so a crash never leaves half-updated sessions behind.
 */
export class SignalDevice {
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(
    private state: SignalState,
    private readonly store: StateStore,
    /** This device's own address: the account's user id and its Signal device number. */
    private self: { userId: string; signalDeviceId: number } | null,
  ) {}

  static async open(store: StateStore): Promise<SignalDevice> {
    let state = await store.load();
    if (!state) {
      state = {
        identityKeyPair: b64(S.IdentityKeyPair.generate().serialize()),
        // Registration ids are 14-bit numbers that help detect reinstalls.
        registrationId: 1 + Math.floor(Math.random() * 16379),
        nextPreKeyId: 1,
        preKeys: {},
        signedPreKeys: {},
        kyberPreKeys: {},
        sessions: {},
        identities: {},
      };
      await store.save(state);
    }
    return new SignalDevice(state, store, null);
  }

  /** Must be called once the server has assigned this device its Signal number. */
  setAddress(userId: string, signalDeviceId: number) {
    this.self = { userId, signalDeviceId };
  }

  get identityKey(): string {
    return b64(this.identity().publicKey.serialize());
  }

  private identity() {
    return S.IdentityKeyPair.deserialize(unb64(this.state.identityKeyPair));
  }

  private run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next.then(async (v) => {
      await this.store.save(this.state);
      return v;
    });
  }

  /** Builds the key upload for this device, creating signed, Kyber and one-time pre-keys as needed. */
  keyUpload(deviceId: string, signWithDeviceKey: (payload: Uint8Array) => string): Promise<UploadKeysRequest> {
    return this.run(async () => {
      const id = this.identity();
      if (!this.state.signedPreKeys[SIGNED_PREKEY_ID]) {
        const priv = S.PrivateKey.generate();
        const sig = id.privateKey.sign(priv.getPublicKey().serialize());
        this.state.signedPreKeys[SIGNED_PREKEY_ID] = b64(
          S.SignedPreKeyRecord.new(SIGNED_PREKEY_ID, Date.now(), priv.getPublicKey(), priv, sig).serialize(),
        );
      }
      if (!this.state.kyberPreKeys[KYBER_PREKEY_ID]) {
        const kp = S.KEMKeyPair.generate();
        const sig = id.privateKey.sign(kp.getPublicKey().serialize());
        this.state.kyberPreKeys[KYBER_PREKEY_ID] = b64(S.KyberPreKeyRecord.new(KYBER_PREKEY_ID, Date.now(), kp, sig).serialize());
      }
      const spk = S.SignedPreKeyRecord.deserialize(unb64(this.state.signedPreKeys[SIGNED_PREKEY_ID]!));
      const kpk = S.KyberPreKeyRecord.deserialize(unb64(this.state.kyberPreKeys[KYBER_PREKEY_ID]!));
      const identityKey = this.identityKey;
      return {
        registrationId: this.state.registrationId,
        identityKey,
        identitySignature: signWithDeviceKey(signalIdentityPayload(deviceId, identityKey)),
        signedPreKey: { id: spk.id(), publicKey: b64(spk.publicKey().serialize()), signature: b64(spk.signature()) },
        kyberPreKey: { id: kpk.id(), publicKey: b64(kpk.publicKey().serialize()), signature: b64(kpk.signature()) },
        oneTimePreKeys: this.makePreKeys(PREKEY_BATCH),
      };
    });
  }

  /** More one-time pre-keys, for when the server's supply runs low. */
  morePreKeys(count = PREKEY_BATCH): Promise<{ id: number; publicKey: string }[]> {
    return this.run(async () => this.makePreKeys(count));
  }

  private makePreKeys(count: number) {
    const out: { id: number; publicKey: string }[] = [];
    for (let i = 0; i < count; i++) {
      const id = this.state.nextPreKeyId++;
      const priv = S.PrivateKey.generate();
      this.state.preKeys[id] = b64(S.PreKeyRecord.new(id, priv.getPublicKey(), priv).serialize());
      out.push({ id, publicKey: b64(priv.getPublicKey().serialize()) });
    }
    return out;
  }

  hasSession(userId: string, signalDeviceId: number): boolean {
    return `${userId}.${signalDeviceId}` in this.state.sessions;
  }

  /** The identity key we trust for each of these devices, or undefined where we've never talked to it. */
  identityKeysOf(userId: string, signalDeviceIds: number[]): (string | undefined)[] {
    return signalDeviceIds.map((n) => this.state.identities[`${userId}.${n}`]);
  }

  /**
   * Forgets the keys and sessions we hold for a person, so the next message to or
   * from them starts over with whatever keys the server hands out. Only for after
   * the person has confirmed, outside Silo, that their key really changed.
   */
  forgetUser(userId: string): Promise<void> {
    return this.run(async () => {
      const prefix = `${userId}.`;
      for (const k of Object.keys(this.state.identities)) if (k.startsWith(prefix)) delete this.state.identities[k];
      for (const k of Object.keys(this.state.sessions)) if (k.startsWith(prefix)) delete this.state.sessions[k];
    });
  }

  /** Encrypts one plaintext separately for each target device. */
  encrypt(plaintext: Uint8Array, targets: Target[]): Promise<OutgoingCopy[]> {
    return this.run(async () => {
      const me = this.requireSelf();
      const stores = this.stores();
      const out: OutgoingCopy[] = [];
      for (const t of targets) {
        const address = S.ProtocolAddress.new(t.userId, t.signalDeviceId);
        if (!(addrKey(address) in this.state.sessions)) {
          if (!t.bundle) throw new Error(`no session or key bundle for device ${t.deviceId}`);
          await this.startSession(t.userId, t.bundle, address, me, stores);
        }
        try {
          const msg = await S.signalEncrypt(new Uint8Array(plaintext), address, me, stores.session, stores.identity);
          out.push({ deviceId: t.deviceId, type: msg.type() as 2 | 3, body: b64(msg.serialize()) });
        } catch (err) {
          throw this.translate(err, t.userId);
        }
      }
      return out;
    });
  }

  private async startSession(
    userId: string,
    bundle: DeviceBundle,
    address: S.ProtocolAddress,
    me: S.ProtocolAddress,
    stores: ReturnType<SignalDevice['stores']>,
  ) {
    // The device's login key must vouch for its Signal identity, or someone swapped keys.
    if (!verifyEd25519(bundle.identitySignature, signalIdentityPayload(bundle.deviceId, bundle.identityKey), bundle.devicePublicKey)) {
      throw new Error(`device ${bundle.deviceId} has an invalid identity signature`);
    }
    const pb = S.PreKeyBundle.new(
      bundle.registrationId,
      bundle.signalDeviceId,
      bundle.oneTimePreKey?.id ?? null,
      bundle.oneTimePreKey ? S.PublicKey.deserialize(unb64(bundle.oneTimePreKey.publicKey)) : null,
      bundle.signedPreKey.id,
      S.PublicKey.deserialize(unb64(bundle.signedPreKey.publicKey)),
      unb64(bundle.signedPreKey.signature),
      S.PublicKey.deserialize(unb64(bundle.identityKey)),
      bundle.kyberPreKey.id,
      S.KEMPublicKey.deserialize(unb64(bundle.kyberPreKey.publicKey)),
      unb64(bundle.kyberPreKey.signature),
    );
    try {
      await S.processPreKeyBundle(pb, address, me, stores.session, stores.identity);
    } catch (err) {
      throw this.translate(err, userId);
    }
  }

  /** Decrypts an envelope from another device. */
  decrypt(envelope: { senderUserId: string; senderSignalDeviceId: number; type: 2 | 3; body: string }): Promise<Uint8Array> {
    return this.run(async () => {
      const me = this.requireSelf();
      const stores = this.stores();
      const from = S.ProtocolAddress.new(envelope.senderUserId, envelope.senderSignalDeviceId);
      try {
        if (envelope.type === 3) {
          return await S.signalDecryptPreKey(
            S.PreKeySignalMessage.deserialize(unb64(envelope.body)),
            from,
            me,
            stores.session,
            stores.identity,
            stores.preKey,
            stores.signedPreKey,
            stores.kyberPreKey,
          );
        }
        return await S.signalDecrypt(S.SignalMessage.deserialize(unb64(envelope.body)), from, me, stores.session, stores.identity);
      } catch (err) {
        throw this.translate(err, envelope.senderUserId);
      }
    });
  }

  /**
   * Sealed sender: encrypts for each target device so that only the recipient can
   * tell who sent it. The certificate, issued by the server, proves to the
   * recipient which account and device we are.
   */
  sealedEncrypt(plaintext: Uint8Array, targets: Target[], senderCertificate: string): Promise<OutgoingCopy[]> {
    return this.run(async () => {
      const me = this.requireSelf();
      const stores = this.stores();
      const cert = S.SenderCertificate.deserialize(unb64(senderCertificate));
      const out: OutgoingCopy[] = [];
      for (const t of targets) {
        const address = S.ProtocolAddress.new(t.userId, t.signalDeviceId);
        if (!(addrKey(address) in this.state.sessions)) {
          if (!t.bundle) throw new Error(`no session or key bundle for device ${t.deviceId}`);
          await this.startSession(t.userId, t.bundle, address, me, stores);
        }
        try {
          const body = await S.sealedSenderEncryptMessage(new Uint8Array(plaintext), address, cert, stores.session, stores.identity);
          out.push({ deviceId: t.deviceId, type: SEALED, body: b64(body) });
        } catch (err) {
          throw this.translate(err, t.userId);
        }
      }
      return out;
    });
  }

  /**
   * Opens a sealed-sender envelope. libsignal checks the sender certificate against
   * the server's trust root and that it hasn't expired, and the sender's identity
   * against the session, so the sender named here is the one who encrypted it.
   */
  sealedDecrypt(body: string, trustRoot: string): Promise<{ senderUserId: string; senderSignalDeviceId: number; plaintext: Uint8Array }> {
    return this.run(async () => {
      const me = this.requireSelf();
      const stores = this.stores();
      let res: S.SealedSenderDecryptionResult;
      try {
        res = await S.sealedSenderDecryptMessage(
          unb64(body),
          S.PublicKey.deserialize(unb64(trustRoot)),
          Date.now(),
          null,
          me.name(),
          me.deviceId(),
          stores.session,
          stores.identity,
          stores.preKey,
          stores.signedPreKey,
          stores.kyberPreKey,
        );
      } catch (err) {
        if (err instanceof S.LibSignalErrorBase && err.code === S.ErrorCode.UntrustedIdentity) {
          // The certificate names the sender even when their key changed.
          const usmc = await S.sealedSenderDecryptToUsmc(unb64(body), stores.identity).catch(() => null);
          throw new IdentityChangedError(usmc?.senderCertificate().senderUuid() ?? 'unknown');
        }
        throw err instanceof Error ? err : new Error(String(err));
      }
      return { senderUserId: res.senderUuid(), senderSignalDeviceId: res.deviceId(), plaintext: res.message() };
    });
  }

  /**
   * Our sender key for one channel distribution, as a distribution message to hand
   * to each member device over its own pairwise session. Creates the key if needed.
   */
  senderKeyDistribution(distributionId: string): Promise<string> {
    return this.run(async () => {
      const msg = await S.SenderKeyDistributionMessage.create(this.requireSelf(), distributionId, this.senderKeyStore());
      return b64(msg.serialize());
    });
  }

  /**
   * Stores someone's sender key. Only call this with a distribution message that
   * arrived inside a pairwise Signal message from that same device, which is what
   * proves who it came from.
   */
  processSenderKeyDistribution(senderUserId: string, senderSignalDeviceId: number, skdm: string): Promise<void> {
    return this.run(async () => {
      const from = S.ProtocolAddress.new(senderUserId, senderSignalDeviceId);
      await S.processSenderKeyDistributionMessage(from, S.SenderKeyDistributionMessage.deserialize(unb64(skdm)), this.senderKeyStore());
    });
  }

  /** Encrypts once for everyone holding our sender key for this distribution. */
  groupEncrypt(distributionId: string, plaintext: Uint8Array): Promise<string> {
    return this.run(async () => {
      const me = this.requireSelf();
      const store = this.senderKeyStore();
      if (!(await store.getSenderKey(me, distributionId))) await S.SenderKeyDistributionMessage.create(me, distributionId, store);
      const msg = await S.groupEncrypt(me, distributionId, store, new Uint8Array(plaintext));
      return b64(msg.serialize());
    });
  }

  /** Decrypts a channel message, checking it was signed by the sender key we hold for that device. */
  groupDecrypt(senderUserId: string, senderSignalDeviceId: number, body: string): Promise<{ distributionId: string; plaintext: Uint8Array }> {
    return this.run(async () => {
      const from = S.ProtocolAddress.new(senderUserId, senderSignalDeviceId);
      const bytes = unb64(body);
      const distributionId = S.SenderKeyMessage.deserialize(bytes).distributionId();
      if (!this.state.senderKeys?.[`${addrKey(from)}::${distributionId}`]) throw new MissingSenderKeyError();
      try {
        return { distributionId, plaintext: await S.groupDecrypt(from, this.senderKeyStore(), bytes) };
      } catch (err) {
        if (err instanceof S.LibSignalErrorBase && err.code === S.ErrorCode.InvalidSenderKeySession) throw new MissingSenderKeyError();
        throw err;
      }
    });
  }

  private senderKeyStore() {
    const keys = (this.state.senderKeys ??= {});
    return new (class extends S.SenderKeyStore {
      async saveSenderKey(a: S.ProtocolAddress, distributionId: string, r: S.SenderKeyRecord) {
        keys[`${addrKey(a)}::${distributionId}`] = b64(r.serialize());
      }
      async getSenderKey(a: S.ProtocolAddress, distributionId: string) {
        const v = keys[`${addrKey(a)}::${distributionId}`];
        return v ? S.SenderKeyRecord.deserialize(unb64(v)) : null;
      }
    })();
  }

  /** How many one-time pre-keys this device still holds privately. */
  get preKeyCount() {
    return Object.keys(this.state.preKeys).length;
  }

  private requireSelf() {
    if (!this.self) throw new Error('device address not set; upload keys first');
    return S.ProtocolAddress.new(this.self.userId, this.self.signalDeviceId);
  }

  private translate(err: unknown, userId: string): Error {
    if (err instanceof S.LibSignalErrorBase && err.code === S.ErrorCode.UntrustedIdentity) return new IdentityChangedError(userId);
    return err instanceof Error ? err : new Error(String(err));
  }

  private stores() {
    const st = this.state;
    const self = this;
    const session = new (class extends S.SessionStore {
      async saveSession(a: S.ProtocolAddress, r: S.SessionRecord) {
        st.sessions[addrKey(a)] = b64(r.serialize());
      }
      async getSession(a: S.ProtocolAddress) {
        const v = st.sessions[addrKey(a)];
        return v ? S.SessionRecord.deserialize(unb64(v)) : null;
      }
      async getExistingSessions(as: S.ProtocolAddress[]) {
        return as.map((a) => {
          const v = st.sessions[addrKey(a)];
          if (!v) throw new Error(`no session for ${addrKey(a)}`);
          return S.SessionRecord.deserialize(unb64(v));
        });
      }
    })();
    const identity = new (class extends S.IdentityKeyStore {
      async getIdentityKey() {
        return self.identity().privateKey;
      }
      async getLocalRegistrationId() {
        return st.registrationId;
      }
      async saveIdentity(a: S.ProtocolAddress, key: S.PublicKey) {
        const prev = st.identities[addrKey(a)];
        st.identities[addrKey(a)] = b64(key.serialize());
        return prev && !sameBytes(unb64(prev), key.serialize()) ? S.IdentityChange.ReplacedExisting : S.IdentityChange.NewOrUnchanged;
      }
      async isTrustedIdentity(a: S.ProtocolAddress, key: S.PublicKey) {
        const prev = st.identities[addrKey(a)];
        return !prev || sameBytes(unb64(prev), key.serialize());
      }
      async getIdentity(a: S.ProtocolAddress) {
        const v = st.identities[addrKey(a)];
        return v ? S.PublicKey.deserialize(unb64(v)) : null;
      }
    })();
    const preKey = new (class extends S.PreKeyStore {
      async savePreKey(id: number, r: S.PreKeyRecord) {
        st.preKeys[id] = b64(r.serialize());
      }
      async getPreKey(id: number) {
        const v = st.preKeys[id];
        if (!v) throw new Error(`unknown pre-key ${id}`);
        return S.PreKeyRecord.deserialize(unb64(v));
      }
      async removePreKey(id: number) {
        delete st.preKeys[id];
      }
    })();
    const signedPreKey = new (class extends S.SignedPreKeyStore {
      async saveSignedPreKey(id: number, r: S.SignedPreKeyRecord) {
        st.signedPreKeys[id] = b64(r.serialize());
      }
      async getSignedPreKey(id: number) {
        const v = st.signedPreKeys[id];
        if (!v) throw new Error(`unknown signed pre-key ${id}`);
        return S.SignedPreKeyRecord.deserialize(unb64(v));
      }
    })();
    const kyberPreKey = new (class extends S.KyberPreKeyStore {
      async saveKyberPreKey(id: number, r: S.KyberPreKeyRecord) {
        st.kyberPreKeys[id] = b64(r.serialize());
      }
      async getKyberPreKey(id: number) {
        const v = st.kyberPreKeys[id];
        if (!v) throw new Error(`unknown Kyber pre-key ${id}`);
        return S.KyberPreKeyRecord.deserialize(unb64(v));
      }
      // Our only Kyber pre-key is a last-resort key that stays valid for reuse.
      async markKyberPreKeyUsed() {}
    })();
    return { session, identity, preKey, signedPreKey, kyberPreKey };
  }
}
