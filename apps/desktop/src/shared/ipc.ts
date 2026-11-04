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
  /** Subscribes to live updates such as new messages. Returns an unsubscribe function. */
  onEvent(listener: (event: AppEvent) => void): () => void;
  /** Everything to do with servers goes through one call, validated in the main process. */
  space<A extends SpaceAction>(action: A): Promise<Result<SpaceResult<A>>>;
}

export type Role = 'owner' | 'admin' | 'member';

export interface DmMessage {
  id: string;
  from: 'me' | 'them';
  text: string;
  sentAt: string;
  /** Set when a message arrived but couldn't be read. */
  error?: string;
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
}

export interface ChannelView {
  channelId: string;
  messages: ChannelMessageView[];
}

export type ChannelAction =
  | { kind: 'get'; spaceId: string; channelId: string }
  | { kind: 'send'; spaceId: string; channelId: string; text: string };

export type AppEvent =
  | { type: 'messages'; peerUserId: string }
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
  event: 'silo:event',
} as const;
