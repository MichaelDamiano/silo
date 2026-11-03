import { describe, expect, it } from 'vitest';
import { ChannelName, canManage } from './spaces.js';

describe('spaces', () => {
  it('normalises channel names', () => {
    expect(ChannelName.parse(' General ')).toBe('general');
    expect(ChannelName.safeParse('has space').success).toBe(false);
    expect(ChannelName.safeParse('-leading').success).toBe(false);
  });

  it('lets owners manage everyone but owners, and admins only members', () => {
    expect(canManage('owner', 'admin')).toBe(true);
    expect(canManage('owner', 'owner')).toBe(false);
    expect(canManage('admin', 'member')).toBe(true);
    expect(canManage('admin', 'admin')).toBe(false);
    expect(canManage('admin')).toBe(true);
    expect(canManage('member')).toBe(false);
    expect(canManage('member', 'member')).toBe(false);
  });
});
