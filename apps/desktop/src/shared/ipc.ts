/** The only API the renderer can call. It never exposes the device's secret key or session token. */
export interface SiloBridge {
  deviceInfo(): Promise<DeviceInfo>;
  signup(input: SignupInput): Promise<Result<{ account: AccountView; recoveryKey: string }>>;
  login(input: { serverUrl: string }): Promise<Result<AccountView>>;
  logout(): Promise<void>;
  /** A new device asks to join an account; returns the code to type on an existing device. */
  requestLink(input: { serverUrl: string; username: string; deviceName: string }): Promise<Result<LinkTicket>>;
  /** Checks whether the waiting device was approved, and signs in if it was. */
  checkLink(): Promise<Result<AccountView | null>>;
  /** On a signed-in device: shows which device is waiting behind a pairing code. */
  lookupLink(input: { pairingCode: string }): Promise<Result<PendingDevice>>;
  /** Approves the device found by the last lookupLink call. */
  approveLink(): Promise<Result<AccountView>>;
  revokeDevice(input: { deviceId: string }): Promise<Result<AccountView>>;
  recover(input: RecoverInput): Promise<Result<{ account: AccountView; recoveryKey: string }>>;
  rotateRecoveryKey(): Promise<Result<{ recoveryKey: string }>>;
  /** Creates a code that lets someone new sign up. */
  createAccountInvite(): Promise<Result<{ code: string; expiresAt: string; maxUses: number }>>;
  /** Direct messages: list conversations, open one, or send. */
  dm<A extends DmAction>(action: A): Promise<Result<DmResult<A>>>;
  /** Encrypted channel messages: open a channel's history, or send to it. */
  channel(action: ChannelAction): Promise<Result<ChannelView>>;
  /** Connection settings: the address in use, the server's other addresses, and Tor. */
  connection(action: ConnectionAction): Promise<Result<ConnectionView>>;
  /** Subscribes to live updates such as new messages. Returns an unsubscribe function. */
  onEvent(listener: (event: AppEvent) => void): () => void;
  /** Everything to do with servers goes through one call, validated in the main process. */
  space<A extends SpaceAction>(action: A): Promise<Result<SpaceResult<A>>>;
  /** Blocking, safety numbers, and reports to moderators. */
  safety<A extends SafetyAction>(action: A): Promise<Result<SafetyResult<A>>>;
}

export type Role = 'owner' | 'admin' | 'member';

export interface DmMessage {
  id: string;
  from: 'me' | 'them';
  text: string;
  sentAt: string;
  /** Set when a message arrived but couldn't be read. */
  error?: string;
  /** Extra information, such as a message that so far only went over the local network. */
  note?: string;
}

export interface ConversationSummary {
  peerUserId: string;
  peerUsername: string;
  last: DmMessage | null;
}

export interface Conversation {
  peerUserId: string;
  peerUsername: string;
  messages: DmMessage[];
}

export type DmAction =
  | { kind: 'list' }
  | { kind: 'get'; peerUserId: string; peerUsername?: string }
  | { kind: 'send'; peerUserId: string; peerUsername: string; text: string };

export type DmResult<A extends DmAction> = A['kind'] extends 'list' ? ConversationSummary[] : Conversation;

export interface ChannelMessageView {
  id: string;
  from: 'me' | 'them';
  senderUserId: string;
  senderUsername: string;
  text: string;
  sentAt: string;
  /** Set while a message is waiting for its key, or when it couldn't be read. */
  error?: string;
  note?: string;
  /** The server's number for this message, used when reporting it. */
  seq?: number;
  /** From someone this account blocked; the app hides it unless asked. */
  blocked?: boolean;
}

export interface ChannelView {
  channelId: string;
  messages: ChannelMessageView[];
}

export type ChannelAction =
  | { kind: 'get'; spaceId: string; channelId: string }
  | { kind: 'send'; spaceId: string; channelId: string; text: string };

export interface TorSettings {
  proxyHost: string;
  proxyPort: number;
  always: boolean;
}

export interface ConnectionView {
  tor: TorSettings;
  current: { endpoint: string; viaTor: boolean } | null;
  /** Short fingerprint of the server's pinned identity key. */
  serverFingerprint: string | null;
  addresses: { endpoint: string; published: boolean; onion: boolean }[];
  lan: { enabled: boolean; peers: string[] };
}

export type ConnectionAction =
  | { kind: 'get' }
  | ({ kind: 'setTor' } & TorSettings)
  | { kind: 'setLan'; enabled: boolean }
  | { kind: 'addAddress'; address: string }
  | { kind: 'removeAddress'; address: string };

export type AppEvent =
  | { type: 'messages'; peerUserId: string }
  | { type: 'connection'; endpoint: string; viaTor: boolean }
  /** Who is linked on the local network right now. */
  | { type: 'lan'; peers: string[] }
  | { type: 'channel'; channelId: string }
  | { type: 'error'; message: string };

export interface SpaceSummary {
  id: string;
  name: string;
  role: Role;
}

export interface SpaceView extends SpaceSummary {
  channels: { id: string; name: string; position: number }[];
  members: { userId: string; username: string; role: Role; joinedAt: string }[];
  bans?: { userId: string; username: string; bannedAt: string }[];
}

export type SpaceAction =
  | { kind: 'list' }
  | { kind: 'create'; name: string }
  | { kind: 'get'; spaceId: string }
  | { kind: 'join'; code: string }
  | { kind: 'leave'; spaceId: string }
  | { kind: 'delete'; spaceId: string }
  | { kind: 'createChannel'; spaceId: string; name: string }
  | { kind: 'deleteChannel'; spaceId: string; channelId: string }
  | { kind: 'createInvite'; spaceId: string }
  | { kind: 'kick'; spaceId: string; userId: string }
  | { kind: 'ban'; spaceId: string; userId: string }
  | { kind: 'unban'; spaceId: string; userId: string }
  | { kind: 'setRole'; spaceId: string; userId: string; role: 'admin' | 'member' };

export type SpaceResult<A extends SpaceAction> = A['kind'] extends 'list'
  ? SpaceSummary[]
  : A['kind'] extends 'create' | 'join'
    ? SpaceSummary
    : A['kind'] extends 'createInvite'
      ? { code: string; expiresAt: string; maxUses: number }
      : A['kind'] extends 'leave' | 'delete'
        ? null
        : SpaceView;

export interface DeviceInfo {
  publicKey: string;
  fingerprint: string;
  /** False when the OS keychain is missing and the key could not be stored safely. */
  secureStorage: boolean;
}

export interface SignupInput {
  serverUrl: string;
  inviteCode: string;
  username: string;
  deviceName: string;
}

export interface RecoverInput {
  serverUrl: string;
  username: string;
  recoveryKey: string;
  deviceName: string;
}

export interface LinkTicket {
  pairingCode: string;
  /** This device's fingerprint, to compare with what the approving device shows. */
  fingerprint: string;
  expiresAt: string;
}

export interface PendingDevice {
  deviceName: string;
  fingerprint: string;
  expiresAt: string;
}

export interface AccountView {
  username: string;
  devices: { id: string; name: string; current: boolean; revoked: boolean; createdAt: string; fingerprint: string }[];
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export const IPC = {
  deviceInfo: 'silo:device-info',
  signup: 'silo:signup',
  login: 'silo:login',
  logout: 'silo:logout',
  requestLink: 'silo:request-link',
  checkLink: 'silo:check-link',
  lookupLink: 'silo:lookup-link',
  approveLink: 'silo:approve-link',
  revokeDevice: 'silo:revoke-device',
  recover: 'silo:recover',
  rotateRecoveryKey: 'silo:rotate-recovery-key',
  space: 'silo:space',
  createAccountInvite: 'silo:create-account-invite',
  dm: 'silo:dm',
  channel: 'silo:channel',
  connection: 'silo:connection',
  safety: 'silo:safety',
  event: 'silo:event',
} as const;

export type ReportReason = 'spam' | 'scam' | 'harassment' | 'malware' | 'illegal' | 'other';

export interface BlockedView {
  userId: string;
  username: string;
  blockedAt: string;
}

export interface SafetyView {
  peerUserId: string;
  /** Sixty digits in groups of five, or null until keys are exchanged with every device on both sides. */
  number: string | null;
  /**
   * verified: you compared the number with them and it hasn't changed since.
   * changed: it no longer matches the number you verified, so a device or key was added or replaced.
   */
  status: 'verified' | 'unverified' | 'changed' | 'incomplete';
  theirDevices: number;
  myDevices: number;
}

export interface ReportView {
  id: string;
  channelId: string | null;
  channelName: string | null;
  messageSeq: number | null;
  reporter: { userId: string; username: string } | null;
  reported: { userId: string; username: string; isMember: boolean };
  reason: ReportReason;
  note: string;
  excerpt: string;
  status: 'open' | 'resolved' | 'dismissed';
  createdAt: string;
  /**
   * The server can't read messages, so it can't vouch for the excerpt. This compares
   * it with the copy this device decrypted itself.
   */
  localCopy: 'matches' | 'differs' | 'unavailable' | null;
  localText?: string;
}

export type SafetyAction =
  | { kind: 'blocks' }
  | { kind: 'block'; userId: string }
  | { kind: 'unblock'; userId: string }
  | { kind: 'safetyNumber'; peerUserId: string }
  | { kind: 'verify'; peerUserId: string; number: string }
  | { kind: 'unverify'; peerUserId: string }
  | { kind: 'acceptNewKeys'; peerUserId: string }
  | { kind: 'reportMessage'; spaceId: string; channelId: string; messageId: string; reason: ReportReason; note: string }
  | { kind: 'reportUser'; spaceId: string; userId: string; reason: ReportReason; note: string }
  | { kind: 'reports'; spaceId: string; closed?: boolean }
  | { kind: 'resolveReport'; spaceId: string; reportId: string; status: 'resolved' | 'dismissed' };

export type SafetyResult<A extends SafetyAction> = A['kind'] extends 'blocks' | 'block' | 'unblock'
  ? BlockedView[]
  : A['kind'] extends 'safetyNumber' | 'verify' | 'unverify' | 'acceptNewKeys'
    ? SafetyView
    : A['kind'] extends 'reports' | 'resolveReport'
      ? ReportView[]
      : null;
