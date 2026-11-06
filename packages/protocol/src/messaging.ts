import { z } from 'zod';
import { PublicKey as Ed25519PublicKey, Signature as Ed25519Signature } from './api.js';

const b64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, 'must be base64');
const keyId = z.number().int().min(0).max(0xffffff);
/** Base64 ciphertext for one encrypted copy. A 4000-character message with session setup is well under this. */
export const MAX_CIPHERTEXT = 24 * 1024;

/** Signal keys are libsignal's own serialised form, sent as base64. */
export const UploadKeysRequest = z.object({
  registrationId: z.number().int().min(1).max(16380),
  identityKey: b64.max(64),
  /** Ed25519 signature by the device's login key over the Signal identity key. */
  identitySignature: Ed25519Signature,
  signedPreKey: z.object({ id: keyId, publicKey: b64.max(64), signature: b64.max(128) }),
  kyberPreKey: z.object({ id: keyId, publicKey: b64.max(4096), signature: b64.max(128) }),
  oneTimePreKeys: z.array(z.object({ id: keyId, publicKey: b64.max(64) })).max(200),
});

export const AddPreKeysRequest = z.object({
  oneTimePreKeys: z.array(z.object({ id: keyId, publicKey: b64.max(64) })).min(1).max(200),
});

export const UploadKeysResponse = z.object({ signalDeviceId: z.number().int() });
export const PreKeyCount = z.object({ count: z.number().int() });

export const DeviceBundle = z.object({
  deviceId: z.uuid(),
  signalDeviceId: z.number().int(),
  registrationId: z.number().int(),
  devicePublicKey: Ed25519PublicKey,
  identityKey: b64,
  identitySignature: Ed25519Signature,
  signedPreKey: z.object({ id: keyId, publicKey: b64, signature: b64 }),
  kyberPreKey: z.object({ id: keyId, publicKey: b64, signature: b64 }),
  oneTimePreKey: z.object({ id: keyId, publicKey: b64 }).nullable(),
});

export const UserKeysResponse = z.object({ userId: z.uuid(), username: z.string(), devices: z.array(DeviceBundle) });

/** Signal message types: 2 is a normal message, 3 starts a new session. */
export const SignalMessageType = z.union([z.literal(2), z.literal(3)]);

export const SendMessagesRequest = z.object({
  /** The person the conversation is with. Copies also go to the sender's other devices. */
  recipientUserId: z.uuid(),
  messages: z
    .array(z.object({ deviceId: z.uuid(), type: SignalMessageType, body: b64.max(MAX_CIPHERTEXT) }))
    .min(1)
    .max(128),
});

/** Returned with 409 when the sender's device list is out of date. */
export const MismatchedDevices = z.object({
  error: z.string(),
  missing: z.array(z.uuid()),
  extra: z.array(z.uuid()),
});

/** A sealed-sender message. The sender is hidden from the server, so it only travels inside the encryption. */
export const SEALED_TYPE = 6;

/**
 * Lets someone send you sealed messages. You hand it out inside encrypted messages,
 * and the server only keeps its hash. 16 random bytes, base64url.
 */
export const AccessKey = z.string().regex(/^[A-Za-z0-9_-]{22}$/);
export const ACCESS_KEY_HEADER = 'silo-access-key';

export const SealedSendRequest = z.object({
  messages: z
    .array(z.object({ deviceId: z.uuid(), type: z.literal(SEALED_TYPE), body: b64.max(MAX_CIPHERTEXT) }))
    .min(1)
    .max(128),
});

/** Returned with 409 when a sealed send's device list is out of date. Includes what the sender needs to fix it. */
export const SealedMismatch = z.object({
  error: z.string(),
  devices: z.array(z.object({ deviceId: z.uuid(), signalDeviceId: z.number().int() })),
});

export const SenderCertificateResponse = z.object({ certificate: b64, expiresAt: z.iso.datetime() });
export const SetAccessKeyRequest = z.object({ accessKey: AccessKey });

const SenderFields = z.object({
  senderUserId: z.uuid(),
  senderUsername: z.string(),
  senderDeviceId: z.uuid(),
  senderSignalDeviceId: z.number().int(),
  type: SignalMessageType,
});

/** A sealed envelope has no sender fields: the recipient finds the sender inside it. */
const SealedFields = z.object({
  senderUserId: z.null(),
  senderUsername: z.null(),
  senderDeviceId: z.null(),
  senderSignalDeviceId: z.null(),
  type: z.literal(SEALED_TYPE),
});

/** An envelope whose sender the server knows. */
export const IdentifiedEnvelope = z.object({ id: z.uuid(), ...SenderFields.shape, body: b64, receivedAt: z.iso.datetime() });
export const SealedEnvelope = z.object({ id: z.uuid(), ...SealedFields.shape, body: b64, receivedAt: z.iso.datetime() });
export const Envelope = z.union([IdentifiedEnvelope, SealedEnvelope]);

export const EnvelopeList = z.object({ envelopes: z.array(Envelope) });
export const AckRequest = z.object({ ids: z.array(z.uuid()).min(1).max(500) });

/** Message ids are UUIDs, except placeholders for messages that couldn't be read. */
const MessageRef = z.string().min(1).max(64);

/**
 * One emoji, possibly with skin tone, variation selector or joiners. Plain text isn't
 * allowed, so a reaction can't be used to slip a message or a link past anyone.
 */
export const Emoji = z
  .string()
  .min(1)
  .max(32)
  .regex(/^[\p{Extended_Pictographic}\p{Emoji_Modifier}\p{Regional_Indicator}\u200d\ufe0f\u20e3]+$/u, 'must be an emoji');

/**
 * What a reply points at. The quote is the sender's claim; a recipient that has the
 * original shows its own copy instead, so a reply can't put words in someone's mouth.
 */
export const ReplyRef = z.object({ id: MessageRef, userId: z.uuid(), text: z.string().max(400) });

/** Fields any message can carry: a reply, or a mark that it was forwarded from elsewhere. */
const MessageExtras = {
  replyTo: ReplyRef.optional(),
  /** Forwarded messages say so, but not who wrote them or where they came from. */
  forwarded: z.literal(true).optional(),
};

/** The plaintext inside each Signal message. The server never sees this. */
export const DirectMessagePayload = z.object({
  v: z.literal(1),
  kind: z.literal('dm'),
  id: z.uuid(),
  /** The other person in the conversation, from the point of view of the sender. */
  peerUserId: z.uuid(),
  peerUsername: z.string(),
  sentAt: z.iso.datetime(),
  text: z.string().min(1).max(4000),
  /** The sender's access key, so the recipient can send sealed messages back. */
  accessKey: AccessKey.optional(),
  ...MessageExtras,
});

/** Adds or takes back an emoji reaction to a message in a direct conversation. */
export const DirectReactionPayload = z.object({
  v: z.literal(1),
  kind: z.literal('dmReaction'),
  id: z.uuid(),
  peerUserId: z.uuid(),
  peerUsername: z.string(),
  messageId: MessageRef,
  emoji: Emoji,
  /** False takes the reaction back. */
  on: z.boolean(),
  sentAt: z.iso.datetime(),
  accessKey: AccessKey.optional(),
});

/** Anything that belongs to a direct conversation. */
export const DirectPayload = z.discriminatedUnion('kind', [DirectMessagePayload, DirectReactionPayload]);

export type UploadKeysRequest = z.infer<typeof UploadKeysRequest>;
export type DeviceBundle = z.infer<typeof DeviceBundle>;
export type Envelope = z.infer<typeof Envelope>;
export type IdentifiedEnvelope = z.infer<typeof IdentifiedEnvelope>;
export type SealedEnvelope = z.infer<typeof SealedEnvelope>;
export type SendMessagesRequest = z.infer<typeof SendMessagesRequest>;
export type DirectMessagePayload = z.infer<typeof DirectMessagePayload>;
export type DirectReactionPayload = z.infer<typeof DirectReactionPayload>;
export type DirectPayload = z.infer<typeof DirectPayload>;
export type ReplyRef = z.infer<typeof ReplyRef>;

/**
 * Sent inside a pairwise Signal message to hand over the sender's key for one
 * channel. The pairwise session is what proves which device the key belongs to.
 */
export const SenderKeyPayload = z.object({
  v: z.literal(1),
  kind: z.literal('senderKey'),
  spaceId: z.uuid(),
  channelId: z.uuid(),
  distributionId: z.uuid(),
  skdm: b64.max(1024),
});

/** Anything that can arrive inside a pairwise Signal message. */
export const PairwisePayload = z.discriminatedUnion('kind', [DirectMessagePayload, DirectReactionPayload, SenderKeyPayload]);

/** The plaintext of a channel message, encrypted once with the sender's key. */
export const ChannelMessagePayload = z.object({
  v: z.literal(1),
  kind: z.literal('channel'),
  id: z.uuid(),
  spaceId: z.uuid(),
  channelId: z.uuid(),
  sentAt: z.iso.datetime(),
  text: z.string().min(1).max(4000),
  ...MessageExtras,
});

/** Adds or takes back an emoji reaction to a channel message, encrypted with the sender's key like a message. */
export const ChannelReactionPayload = z.object({
  v: z.literal(1),
  kind: z.literal('reaction'),
  id: z.uuid(),
  spaceId: z.uuid(),
  channelId: z.uuid(),
  messageId: MessageRef,
  emoji: Emoji,
  on: z.boolean(),
  sentAt: z.iso.datetime(),
});

/** Anything that can arrive encrypted with a channel sender key. */
export const ChannelPayload = z.discriminatedUnion('kind', [ChannelMessagePayload, ChannelReactionPayload]);

/** Every member device of a space that can receive encrypted messages, except the caller's. */
export const SpaceDevicesResponse = z.object({
  devices: z.array(
    z.object({ userId: z.uuid(), username: z.string(), deviceId: z.uuid(), signalDeviceId: z.number().int(), publicKey: Ed25519PublicKey }),
  ),
});

/** Pairwise copies of a sender key, for any member devices that don't have it yet. */
export const DistributeSenderKeyRequest = z.object({
  messages: z
    .array(z.object({ deviceId: z.uuid(), type: SignalMessageType, body: b64.max(8 * 1024) }))
    .min(1)
    .max(200),
});

export const PostChannelMessageRequest = z.object({ body: b64.max(MAX_CIPHERTEXT) });

export const ChannelMessage = z.object({
  /** Increases with every message on the server, so a device can ask for everything after the last one it saw. */
  seq: z.number().int(),
  spaceId: z.uuid(),
  channelId: z.uuid(),
  senderUserId: z.uuid(),
  senderUsername: z.string(),
  senderDeviceId: z.uuid(),
  senderSignalDeviceId: z.number().int(),
  body: b64,
  receivedAt: z.iso.datetime(),
});

export const ChannelMessageList = z.object({ messages: z.array(ChannelMessage) });

export type SenderKeyPayload = z.infer<typeof SenderKeyPayload>;
export type PairwisePayload = z.infer<typeof PairwisePayload>;
export type ChannelMessagePayload = z.infer<typeof ChannelMessagePayload>;
export type ChannelReactionPayload = z.infer<typeof ChannelReactionPayload>;
export type ChannelPayload = z.infer<typeof ChannelPayload>;
export type ChannelMessage = z.infer<typeof ChannelMessage>;
