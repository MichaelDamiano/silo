import { BlockList, ReportList, ReportReason } from '@silo/protocol';
import { formatSafetyNumber } from '@silo/signal';
import { z } from 'zod';
import type { BlockedView, ReportView, SafetyAction, SafetyView } from '../shared/ipc.js';
import type { Messenger } from './messenger.js';
import type { Vault } from './vault.js';

const id = z.uuid();
const note = z.string().max(500);

/** Everything the renderer sends is untrusted, so check its shape before acting on it. */
export const SafetyActionSchema: z.ZodType<SafetyAction> = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('blocks') }),
  z.object({ kind: z.literal('block'), userId: id }),
  z.object({ kind: z.literal('unblock'), userId: id }),
  z.object({ kind: z.literal('safetyNumber'), peerUserId: id }),
  z.object({ kind: z.literal('verify'), peerUserId: id, number: z.string().regex(/^[\d ]{60,71}$/) }),
  z.object({ kind: z.literal('unverify'), peerUserId: id }),
  z.object({ kind: z.literal('acceptNewKeys'), peerUserId: id }),
  z.object({ kind: z.literal('reportMessage'), spaceId: id, channelId: id, messageId: z.string().max(64), reason: ReportReason, note }),
  z.object({ kind: z.literal('reportUser'), spaceId: id, userId: id, reason: ReportReason, note }),
  z.object({ kind: z.literal('reports'), spaceId: id, closed: z.boolean().optional() }),
  z.object({ kind: z.literal('resolveReport'), spaceId: id, reportId: id, status: z.enum(['resolved', 'dismissed']) }),
]);

type Request = <T>(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, body: unknown, parse: (v: unknown) => T) => Promise<T>;

/** Safety numbers this account has checked with people, by their user id. Kept in the encrypted vault. */
interface Trust {
  userId: string;
  verified: Record<string, string>;
}

/**
 * Blocking, safety numbers and reports for one signed-in account. Blocks live on
 * the server, so every device of the account drops the same people.
 */
export class Safety {
  private trust: Trust;
  private blocked: BlockedView[] = [];

  private constructor(
    private readonly userId: string,
    private readonly vault: Vault,
    private readonly request: Request,
    private readonly messenger: () => Messenger | undefined,
    trust: Trust | null,
  ) {
    this.trust = trust?.userId === userId ? trust : { userId, verified: {} };
  }

  static async open(userId: string, vault: Vault, request: Request, messenger: () => Messenger | undefined) {
    const s = new Safety(userId, vault, request, messenger, await vault.read<Trust>('trust'));
    await s.refreshBlocks().catch(() => undefined);
    return s;
  }

  private async refreshBlocks() {
    this.blocked = (await this.request('GET', '/v1/blocks', undefined, (v) => BlockList.parse(v))).blocked;
    this.messenger()?.setBlocked(this.blocked.map((b) => b.userId));
    return this.blocked;
  }

  blockedIds() {
    return this.blocked.map((b) => b.userId);
  }

  private need() {
    const m = this.messenger();
    if (!m) throw new Error('Encrypted messaging isn’t running on this device.');
    return m;
  }

  private async safetyView(peerUserId: string): Promise<SafetyView> {
    const s = await this.need().safety(peerUserId);
    const verified = this.trust.verified[peerUserId];
    const status = !s.number ? (verified ? 'changed' : 'incomplete') : !verified ? 'unverified' : verified === s.number ? 'verified' : 'changed';
    return {
      peerUserId,
      number: s.number ? formatSafetyNumber(s.number) : null,
      status,
      theirDevices: s.theirDevices,
      myDevices: s.myDevices,
    };
  }

  private async saveTrust() {
    await this.vault.write('trust', this.trust);
  }

  private async reports(spaceId: string, closed: boolean): Promise<ReportView[]> {
    const { reports } = await this.request('GET', `/v1/spaces/${spaceId}/reports?status=${closed ? 'closed' : 'open'}`, undefined, (v) =>
      ReportList.parse(v),
    );
    const m = this.messenger();
    return reports.map((r) => {
      if (!r.channelId || !r.messageSeq) return { ...r, localCopy: null };
      const mine = m?.channelMessage(r.channelId, r.messageSeq);
      if (!mine || mine.error) return { ...r, localCopy: 'unavailable' };
      return { ...r, localCopy: mine.text === r.excerpt ? 'matches' : 'differs', localText: mine.text };
    });
  }

  async run(input: unknown): Promise<unknown> {
    const a = SafetyActionSchema.parse(input);
    switch (a.kind) {
      case 'blocks':
        return this.refreshBlocks();
      case 'block':
        if (a.userId === this.userId) throw new Error("You can't block yourself.");
        await this.request('PUT', `/v1/blocks/${a.userId}`, undefined, () => null);
        return this.refreshBlocks();
      case 'unblock':
        await this.request('DELETE', `/v1/blocks/${a.userId}`, undefined, () => null);
        return this.refreshBlocks();
      case 'safetyNumber':
        return this.safetyView(a.peerUserId);
      case 'verify': {
        const view = await this.safetyView(a.peerUserId);
        // Only the number the person actually compared can be marked as checked.
        if (!view.number || view.number.replace(/ /g, '') !== a.number.replace(/ /g, '')) {
          throw new Error('The safety number changed while you were checking it. Compare the new one.');
        }
        this.trust.verified[a.peerUserId] = view.number.replace(/ /g, '');
        await this.saveTrust();
        return this.safetyView(a.peerUserId);
      }
      case 'unverify':
        delete this.trust.verified[a.peerUserId];
        await this.saveTrust();
        return this.safetyView(a.peerUserId);
      case 'acceptNewKeys':
        await this.need().acceptNewKeys(a.peerUserId);
        delete this.trust.verified[a.peerUserId];
        await this.saveTrust();
        return this.safetyView(a.peerUserId);
      case 'reportMessage': {
        const msg = this.need().channel(a.channelId).messages.find((x) => x.id === a.messageId);
        if (!msg || msg.from === 'me') throw new Error('That message can’t be reported.');
        if (!msg.seq) throw new Error('That message hasn’t reached the server yet. Try again once it has.');
        await this.request(
          'POST',
          `/v1/spaces/${a.spaceId}/reports`,
          {
            reportedUserId: msg.senderUserId,
            channelId: a.channelId,
            messageSeq: msg.seq,
            reason: a.reason,
            note: a.note,
            excerpt: msg.error ? '' : msg.text.slice(0, 2000),
          },
          () => null,
        );
        return null;
      }
      case 'reportUser':
        await this.request('POST', `/v1/spaces/${a.spaceId}/reports`, { reportedUserId: a.userId, reason: a.reason, note: a.note }, () => null);
        return null;
      case 'reports':
        return this.reports(a.spaceId, a.closed ?? false);
      case 'resolveReport':
        await this.request('POST', `/v1/spaces/${a.spaceId}/reports/${a.reportId}/resolve`, { status: a.status }, () => null);
        return this.reports(a.spaceId, false);
    }
  }
}
