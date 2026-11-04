import { z } from 'zod';
import { Username } from './api.js';

export const ReportReason = z.enum(['spam', 'scam', 'harassment', 'malware', 'illegal', 'other']);
export type ReportReason = z.infer<typeof ReportReason>;

export const BlockList = z.object({
  blocked: z.array(z.object({ userId: z.uuid(), username: Username, blockedAt: z.iso.datetime() })),
});
export type BlockList = z.infer<typeof BlockList>;

export const CreateReportRequest = z.object({
  reportedUserId: z.uuid(),
  channelId: z.uuid().optional(),
  /** The channel message's sequence number, so moderators can find it in their own copy. */
  messageSeq: z.number().int().positive().optional(),
  reason: ReportReason,
  note: z.string().trim().max(500).default(''),
  /** The reported text as the reporter saw it. The server can't check it; moderators can. */
  excerpt: z.string().max(2000).default(''),
});
export type CreateReportRequest = z.infer<typeof CreateReportRequest>;

export const ReportStatus = z.enum(['open', 'resolved', 'dismissed']);
export const Report = z.object({
  id: z.uuid(),
  channelId: z.uuid().nullable(),
  channelName: z.string().nullable(),
  messageSeq: z.number().int().nullable(),
  reporter: z.object({ userId: z.uuid(), username: Username }).nullable(),
  reported: z.object({ userId: z.uuid(), username: Username, isMember: z.boolean() }),
  reason: ReportReason,
  note: z.string(),
  excerpt: z.string(),
  status: ReportStatus,
  createdAt: z.iso.datetime(),
  resolvedAt: z.iso.datetime().nullable(),
});
export type Report = z.infer<typeof Report>;
export const ReportList = z.object({ reports: z.array(Report) });
export const ResolveReportRequest = z.object({ status: z.enum(['resolved', 'dismissed']) });
