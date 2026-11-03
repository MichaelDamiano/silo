import { z } from 'zod';
import { PublicKey as Ed25519PublicKey, Signature as Ed25519Signature } from './api.js';

const b64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, 'must be base64');
const keyId = z.number().int().min(0).max(0xffffff);

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
    .array(z.object({ deviceId: z.uuid(), type: SignalMessageType, body: b64.max(96 * 1024) }))
    .min(1)
    .max(128),
});

/** Returned with 409 when the sender's device list is out of date. */
export const MismatchedDevices = z.object({
  error: z.string(),
  missing: z.array(z.uuid()),
  extra: z.array(z.uuid()),
});

export const Envelope = z.object({
  id: z.uuid(),
  senderUserId: z.uuid(),
  senderUsername: z.string(),
  senderDeviceId: z.uuid(),
  senderSignalDeviceId: z.number().int(),
  type: SignalMessageType,
  body: b64,
  receivedAt: z.iso.datetime(),
});

export const EnvelopeList = z.object({ envelopes: z.array(Envelope) });
export const AckRequest = z.object({ ids: z.array(z.uuid()).min(1).max(500) });

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
});

export type UploadKeysRequest = z.infer<typeof UploadKeysRequest>;
export type DeviceBundle = z.infer<typeof DeviceBundle>;
export type Envelope = z.infer<typeof Envelope>;
export type SendMessagesRequest = z.infer<typeof SendMessagesRequest>;
export type DirectMessagePayload = z.infer<typeof DirectMessagePayload>;
