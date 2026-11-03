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
  challengeId: z.uuid(),
  signature: Signature,
});

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
