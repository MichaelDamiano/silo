import { z } from 'zod';
import { PublicKey, Signature } from './api.js';
import { MAX_CIPHERTEXT, SignalMessageType } from './messaging.js';

const b64 = z.string().regex(/^[A-Za-z0-9+/]*={0,2}$/, 'must be base64');

/**
 * Broadcast on the local network so devices can find each other. It says only
 * that a Silo device is listening on a port, not who it belongs to.
 */
export const LanBeacon = z.object({
  silo: z.literal(1),
  /** Random for each run of the app, so devices don't connect to themselves or twice. */
  id: z.string().regex(/^[A-Za-z0-9_-]{16,32}$/),
  port: z.number().int().min(1024).max(65535),
});

/** First message each side sends on a new link: a fresh X25519 key and who it claims to be. */
export const LanHello = z.object({
  v: z.literal(1),
  deviceId: z.uuid(),
  ephemeral: PublicKey,
});

/** Second message: an Ed25519 signature by the device's login key over both hellos. */
export const LanProof = z.object({ signature: Signature });

/** What travels over an established, encrypted link. Sender details come from the link, never the frame. */
export const LanFrame = z.discriminatedUnion('t', [
  /** A pairwise Signal message for the receiving device. */
  z.object({ t: z.literal('envelope'), type: SignalMessageType, body: b64.max(MAX_CIPHERTEXT) }),
  /** A channel message encrypted with the sender's sender key. */
  z.object({ t: z.literal('channel'), spaceId: z.uuid(), channelId: z.uuid(), body: b64.max(MAX_CIPHERTEXT) }),
]);

export type LanBeacon = z.infer<typeof LanBeacon>;
export type LanHello = z.infer<typeof LanHello>;
export type LanFrame = z.infer<typeof LanFrame>;
