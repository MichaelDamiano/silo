import {
  SpaceDetail,
  SpaceInviteResponse,
  SpaceList,
  SpaceSummary,
} from '@silo/protocol';
import { z } from 'zod';
import type { SpaceAction } from '../shared/ipc.js';

const id = z.uuid();

/** Everything the renderer sends is untrusted, so check its shape before acting on it. */
export const SpaceActionSchema: z.ZodType<SpaceAction> = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('list') }),
  z.object({ kind: z.literal('create'), name: z.string().max(64) }),
  z.object({ kind: z.literal('get'), spaceId: id }),
  z.object({ kind: z.literal('join'), code: z.string().max(128) }),
  z.object({ kind: z.literal('leave'), spaceId: id }),
  z.object({ kind: z.literal('delete'), spaceId: id }),
  z.object({ kind: z.literal('createChannel'), spaceId: id, name: z.string().max(64) }),
  z.object({ kind: z.literal('deleteChannel'), spaceId: id, channelId: id }),
  z.object({ kind: z.literal('createInvite'), spaceId: id }),
  z.object({ kind: z.literal('kick'), spaceId: id, userId: id }),
  z.object({ kind: z.literal('ban'), spaceId: id, userId: id }),
  z.object({ kind: z.literal('unban'), spaceId: id, userId: id }),
  z.object({ kind: z.literal('setRole'), spaceId: id, userId: id, role: z.enum(['admin', 'member']) }),
]);

type Request = <T>(method: 'GET' | 'POST' | 'DELETE', path: string, body: unknown, parse: (v: unknown) => T) => Promise<T>;

/** Turns a space action into API calls. After a change it returns the fresh server view. */
export async function runSpaceAction(input: unknown, request: Request): Promise<unknown> {
  const a = SpaceActionSchema.parse(input);
  const s = (spaceId: string) => `/v1/spaces/${spaceId}`;
  const none = () => null;
  const view = (spaceId: string) => request('GET', s(spaceId), undefined, (v) => SpaceDetail.parse(v));

  switch (a.kind) {
    case 'list':
      return (await request('GET', '/v1/spaces', undefined, (v) => SpaceList.parse(v))).spaces;
    case 'create':
      return request('POST', '/v1/spaces', { name: a.name }, (v) => SpaceSummary.parse(v));
    case 'get':
      return view(a.spaceId);
    case 'join':
      return request('POST', '/v1/space-invites/join', { code: a.code.trim() }, (v) => SpaceSummary.parse(v));
    case 'leave':
      return request('POST', `${s(a.spaceId)}/leave`, {}, none);
    case 'delete':
      return request('DELETE', s(a.spaceId), undefined, none);
    case 'createChannel':
      await request('POST', `${s(a.spaceId)}/channels`, { name: a.name }, none);
      return view(a.spaceId);
    case 'deleteChannel':
      await request('DELETE', `${s(a.spaceId)}/channels/${a.channelId}`, undefined, none);
      return view(a.spaceId);
    case 'createInvite':
      return request('POST', `${s(a.spaceId)}/invites`, {}, (v) => SpaceInviteResponse.parse(v));
    case 'kick':
    case 'ban':
      await request('POST', `${s(a.spaceId)}/members/${a.userId}/${a.kind}`, {}, none);
      return view(a.spaceId);
    case 'unban':
      await request('DELETE', `${s(a.spaceId)}/bans/${a.userId}`, undefined, none);
      return view(a.spaceId);
    case 'setRole':
      await request('POST', `${s(a.spaceId)}/members/${a.userId}/role`, { role: a.role }, none);
      return view(a.spaceId);
  }
}
