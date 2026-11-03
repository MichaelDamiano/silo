import { z } from 'zod';

const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/, 'must be base64url');

/** Ed25519 public keys are 32 bytes, which is 43 base64url characters. */
export const PublicKey = base64url.length(43);
/** Ed25519 signatures are 64 bytes, which is 86 base64url characters. */
export const Signature = base64url.length(86);

export const Username = z
  .string()
  .regex(/^[a-z0-9_]{3,32}$/, 'use 3 to 32 lowercase letters, digits or underscores');

export const DeviceName = z.string().trim().min(1).max(64);

export const ChallengeRequest = z.object({ devicePublicKey: PublicKey });
export const ChallengeResponse = z.object({ challengeId: z.uuid(), nonce: base64url });

export const SignupRequest = z.object({
  inviteCode: base64url.min(16).max(64),
  username: Username,
  deviceName: DeviceName,
  devicePublicKey: PublicKey,
  recoveryPublicKey: PublicKey,
  challengeId: z.uuid(),
  signature: Signature,
});

/** A new device asks to join an account. It is shown a pairing code to enter on an existing device. */
export const LinkRequest = z.object({
  username: Username,
  deviceName: DeviceName,
  devicePublicKey: PublicKey,
  challengeId: z.uuid(),
  signature: Signature,
});

/** 10 characters from a 32-letter alphabet, so about 50 bits, valid for 10 minutes. */
export const PairingCode = z
  .string()
  .transform((s) => s.replace(/[\s-]/g, '').toUpperCase())
  .pipe(z.string().regex(/^[A-Z2-7]{10}$/, 'pairing code must be 10 letters or digits'));

export const LinkRequestResponse = z.object({ pairingCode: z.string(), expiresAt: z.iso.datetime() });

export const PendingLink = z.object({
  linkId: z.uuid(),
  deviceName: z.string(),
  devicePublicKey: PublicKey,
  fingerprint: z.string(),
  expiresAt: z.iso.datetime(),
});

export const ApproveLinkRequest = z.object({ linkId: z.uuid(), signature: Signature });

export const RecoverRequest = z.object({
  username: Username,
  deviceName: DeviceName,
  devicePublicKey: PublicKey,
  recoveryPublicKey: PublicKey,
  challengeId: z.uuid(),
  deviceSignature: Signature,
  recoverySignature: Signature,
});

export const RotateRecoveryRequest = z.object({ recoveryPublicKey: PublicKey, signature: Signature });

export const LoginRequest = z.object({
  devicePublicKey: PublicKey,
  challengeId: z.uuid(),
  signature: Signature,
});

export const SessionResponse = z.object({
  token: z.string(),
  expiresAt: z.iso.datetime(),
  userId: z.uuid(),
  deviceId: z.uuid(),
});

export const Device = z.object({
  id: z.uuid(),
  name: z.string(),
  publicKey: PublicKey,
  createdAt: z.iso.datetime(),
  revokedAt: z.iso.datetime().nullable(),
  /** The device that vouched for this one, or null for the first device or a recovery. */
  approvedBy: z.uuid().nullable(),
  current: z.boolean(),
});

export const MeResponse = z.object({
  id: z.uuid(),
  username: Username,
  devices: z.array(Device),
});

export const CreateInviteRequest = z.object({
  maxUses: z.number().int().min(1).max(100).default(1),
  expiresInHours: z.number().int().min(1).max(24 * 30).default(72),
});

export const CreateInviteResponse = z.object({
  code: z.string(),
  maxUses: z.number().int(),
  expiresAt: z.iso.datetime(),
});

export const ErrorResponse = z.object({ error: z.string() });

export type ChallengeRequest = z.infer<typeof ChallengeRequest>;
export type ChallengeResponse = z.infer<typeof ChallengeResponse>;
export type SignupRequest = z.infer<typeof SignupRequest>;
export type LoginRequest = z.infer<typeof LoginRequest>;
export type SessionResponse = z.infer<typeof SessionResponse>;
export type Device = z.infer<typeof Device>;
export type MeResponse = z.infer<typeof MeResponse>;
export type CreateInviteRequest = z.infer<typeof CreateInviteRequest>;
export type CreateInviteResponse = z.infer<typeof CreateInviteResponse>;
export type LinkRequest = z.infer<typeof LinkRequest>;
export type LinkRequestResponse = z.infer<typeof LinkRequestResponse>;
export type PendingLink = z.infer<typeof PendingLink>;
export type RecoverRequest = z.infer<typeof RecoverRequest>;
