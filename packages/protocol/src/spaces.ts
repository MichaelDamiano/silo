import { z } from 'zod';
import { Username } from './api.js';

// "Spaces" in the code are what the app calls servers, to keep them apart from the backend server.

export const Role = z.enum(['owner', 'admin', 'member']);
export type Role = z.infer<typeof Role>;

export const SpaceName = z.string().trim().min(1).max(64);
export const ChannelName = z
  .string()
  .trim()
  .toLowerCase()
  .pipe(z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'use up to 32 lowercase letters, digits or dashes'));

export const CreateSpaceRequest = z.object({ name: SpaceName });
export const CreateChannelRequest = z.object({ name: ChannelName });
export const CreateSpaceInviteRequest = z.object({
  maxUses: z.number().int().min(1).max(1000).default(10),
  expiresInHours: z.number().int().min(1).max(24 * 30).default(72),
});
export const JoinSpaceRequest = z.object({ code: z.string().regex(/^[A-Za-z0-9_-]{16,64}$/) });
export const SetRoleRequest = z.object({ role: z.enum(['admin', 'member']) });

export const SpaceSummary = z.object({ id: z.uuid(), name: z.string(), role: Role });
export const Channel = z.object({ id: z.uuid(), name: z.string(), position: z.number().int() });
export const Member = z.object({ userId: z.uuid(), username: Username, role: Role, joinedAt: z.iso.datetime() });
export const Ban = z.object({ userId: z.uuid(), username: Username, bannedAt: z.iso.datetime() });

export const SpaceDetail = z.object({
  id: z.uuid(),
  name: z.string(),
  role: Role,
  channels: z.array(Channel),
  members: z.array(Member),
  /** Only included for owners and admins. */
  bans: z.array(Ban).optional(),
});

export const SpaceList = z.object({ spaces: z.array(SpaceSummary) });
export const SpaceInviteResponse = z.object({ code: z.string(), maxUses: z.number().int(), expiresAt: z.iso.datetime() });

export type SpaceSummary = z.infer<typeof SpaceSummary>;
export type SpaceDetail = z.infer<typeof SpaceDetail>;
export type Channel = z.infer<typeof Channel>;
export type Member = z.infer<typeof Member>;
export type SpaceInviteResponse = z.infer<typeof SpaceInviteResponse>;

/** What each role may do. The server enforces this; clients use it to hide controls. */
export function canManage(actor: Role, target?: Role): boolean {
  if (actor === 'owner') return target !== 'owner';
  if (actor === 'admin') return target === undefined || target === 'member';
  return false;
}
