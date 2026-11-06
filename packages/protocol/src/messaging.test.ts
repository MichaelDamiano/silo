import { describe, expect, it } from 'vitest';
import { ChannelPayload, Emoji, PairwisePayload } from './messaging.js';

const uuid = '6f1c1c8e-6a4b-4f43-9a37-2b0f7e7d4c11';
const at = '2026-11-06T12:00:00.000Z';

describe('emoji reactions', () => {
  it('accepts emoji, with skin tones and joiners', () => {
    for (const e of ['👍', '❤️', '👍🏽', '👨‍👩‍👧', '🇺🇸', '🎉']) expect(Emoji.safeParse(e).success, e).toBe(true);
  });

  it('rejects text, links and digits', () => {
    for (const e of ['', 'lol', 'http://x', '1', '👍 click here', '<b>']) expect(Emoji.safeParse(e).success, e).toBe(false);
  });

  it('parses reactions next to messages', () => {
    const dm = PairwisePayload.parse({ v: 1, kind: 'dmReaction', id: uuid, peerUserId: uuid, peerUsername: 'a', messageId: uuid, emoji: '👍', on: true, sentAt: at });
    expect(dm.kind).toBe('dmReaction');
    const ch = ChannelPayload.parse({ v: 1, kind: 'reaction', id: uuid, spaceId: uuid, channelId: uuid, messageId: uuid, emoji: '🎉', on: false, sentAt: at });
    expect(ch.kind).toBe('reaction');
  });
});

describe('replies and forwarding', () => {
  it('carries a reply and a forwarded mark', () => {
    const p = ChannelPayload.parse({
      v: 1,
      kind: 'channel',
      id: uuid,
      spaceId: uuid,
      channelId: uuid,
      sentAt: at,
      text: 'yes',
      replyTo: { id: uuid, userId: uuid, text: 'are you coming?' },
      forwarded: true,
    });
    expect(p.kind === 'channel' && p.replyTo?.text).toBe('are you coming?');
  });

  it('caps the quoted text', () => {
    const r = ChannelPayload.safeParse({ v: 1, kind: 'channel', id: uuid, spaceId: uuid, channelId: uuid, sentAt: at, text: 'x', replyTo: { id: uuid, userId: uuid, text: 'y'.repeat(401) } });
    expect(r.success).toBe(false);
  });
});
