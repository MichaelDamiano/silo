import { useEffect, useState, type FormEvent } from 'react';
import type { ConversationSummary, Role, SpaceAction, SpaceResult, SpaceSummary, SpaceView } from '../shared/ipc';

/** Mirrors the server's rule: owners manage everyone but owners, admins manage members. */
function canManage(actor: Role, target?: Role) {
  if (actor === 'owner') return target !== 'owner';
  if (actor === 'admin') return target === undefined || target === 'member';
  return false;
}

async function act<A extends SpaceAction>(action: A): Promise<SpaceResult<A>> {
  const result = await window.silo.space(action);
  if (!result.ok) throw new Error(result.error);
  return result.value;
}

export function Sidebar({
  spaces,
  selected,
  onSelect,
  onAccount,
  accountSelected,
  conversations,
  selectedDm,
  onSelectDm,
}: {
  spaces: SpaceSummary[];
  selected?: string;
  onSelect: (id: string | 'new') => void;
  onAccount: () => void;
  accountSelected: boolean;
  conversations: ConversationSummary[];
  selectedDm?: string;
  onSelectDm: (c: ConversationSummary) => void;
}) {
  return (
    <nav className="sidebar" aria-label="Servers">
      <div className="sidebar-title">Servers</div>
      <ul>
        {spaces.map((s) => (
          <li key={s.id}>
            <button className="nav" aria-current={selected === s.id} onClick={() => onSelect(s.id)}>
              {s.name}
            </button>
          </li>
        ))}
      </ul>
      <button className="nav add" aria-current={selected === 'new'} onClick={() => onSelect('new')}>
        + Create or join
      </button>
      <div className="sidebar-title">Direct messages</div>
      <ul>
        {conversations.map((c) => (
          <li key={c.peerUserId}>
            <button className="nav" aria-current={selectedDm === c.peerUserId} onClick={() => onSelectDm(c)}>
              {c.peerUsername}
            </button>
          </li>
        ))}
        {conversations.length === 0 && <li className="muted hint">Open a member's name in a server to message them.</li>}
      </ul>
      <div className="sidebar-spacer" />
      <button className="nav" aria-current={accountSelected} onClick={onAccount}>
        Account and devices
      </button>
    </nav>
  );
}

export function NewSpace({ onDone }: { onDone: (s: SpaceSummary) => void }) {
  const [name, setName] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<SpaceSummary>) {
    setBusy(true);
    setError(undefined);
    try {
      onDone(await fn());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="content">
      <h1>Create a server</h1>
      <form
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          void run(() => act({ kind: 'create', name }));
        }}
      >
        <label htmlFor="space-name">Server name</label>
        <input id="space-name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} />
        <div className="row">
          <button className="primary" type="submit" disabled={busy}>Create server</button>
        </div>
      </form>
      <h2>Join a server</h2>
      <form
        onSubmit={(e: FormEvent) => {
          e.preventDefault();
          void run(() => act({ kind: 'join', code }));
        }}
      >
        <label htmlFor="space-code">Invite code</label>
        <input id="space-code" value={code} onChange={(e) => setCode(e.target.value)} required autoComplete="off" spellCheck={false} />
        <div className="row">
          <button type="submit" disabled={busy}>Join server</button>
        </div>
      </form>
      {error && <div className="error">{error}</div>}
    </div>
  );
}

export function SpacePage({
  spaceId,
  onGone,
  onMessage,
  myUsername,
}: {
  spaceId: string;
  onGone: () => void;
  onMessage: (userId: string, username: string) => void;
  myUsername: string;
}) {
  const [space, setSpace] = useState<SpaceView>();
  const [channelId, setChannelId] = useState<string>();
  const [newChannel, setNewChannel] = useState('');
  const [invite, setInvite] = useState<{ code: string; expiresAt: string; maxUses: number }>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setSpace(undefined);
    setInvite(undefined);
    setChannelId(undefined);
    act({ kind: 'get', spaceId }).then(setSpace, (e: Error) => setError(e.message));
  }, [spaceId]);

  async function run<T>(fn: () => Promise<T>, then: (v: T) => void) {
    setBusy(true);
    setError(undefined);
    try {
      then(await fn());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  if (!space) return <div className="content">{error ? <div className="error">{error}</div> : <p className="muted">Loading…</p>}</div>;

  const manager = canManage(space.role);
  const channel = space.channels.find((c) => c.id === channelId) ?? space.channels[0];

  return (
    <div className="space">
      <section className="channels" aria-label="Channels">
        <div className="sidebar-title">{space.name}</div>
        <ul>
          {space.channels.map((c) => (
            <li key={c.id} className="channel-row">
              <button className="nav" aria-current={channel?.id === c.id} onClick={() => setChannelId(c.id)}>
                # {c.name}
              </button>
              {manager && space.channels.length > 1 && (
                <button
                  className="icon"
                  title={`Delete #${c.name}`}
                  aria-label={`Delete #${c.name}`}
                  disabled={busy}
                  onClick={() => {
                    if (confirm(`Delete #${c.name}?`)) void run(() => act({ kind: 'deleteChannel', spaceId, channelId: c.id }), setSpace);
                  }}
                >
                  ×
                </button>
              )}
            </li>
          ))}
        </ul>
        {manager && (
          <form
            className="inline"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() => act({ kind: 'createChannel', spaceId, name: newChannel }), (v) => {
                setSpace(v);
                setNewChannel('');
              });
            }}
          >
            <input aria-label="New channel name" placeholder="new-channel" value={newChannel} onChange={(e) => setNewChannel(e.target.value)} required />
            <button type="submit" disabled={busy}>Add</button>
          </form>
        )}
      </section>

      <section className="content" aria-label="Messages">
        <h1># {channel?.name}</h1>
        <p className="muted">Channel messages arrive in the next update. Direct messages are already end-to-end encrypted: choose Message next to a member.</p>
        {error && <div className="error">{error}</div>}
      </section>

      <section className="members" aria-label="Members">
        <div className="sidebar-title">Members ({space.members.length})</div>
        <ul>
          {space.members.map((m) => (
            <li key={m.userId} className="member">
              <div>
                {m.username} {m.role !== 'member' && <span className="badge">{m.role}</span>}
                {m.username !== myUsername && (
                  <button className="link" onClick={() => onMessage(m.userId, m.username)}>
                    Message
                  </button>
                )}
              </div>
              {canManage(space.role, m.role) && (
                <div className="member-actions">
                  {space.role === 'owner' && (
                    <button
                      disabled={busy}
                      onClick={() =>
                        void run(() => act({ kind: 'setRole', spaceId, userId: m.userId, role: m.role === 'admin' ? 'member' : 'admin' }), setSpace)
                      }
                    >
                      {m.role === 'admin' ? 'Remove admin' : 'Make admin'}
                    </button>
                  )}
                  <button disabled={busy} onClick={() => void run(() => act({ kind: 'kick', spaceId, userId: m.userId }), setSpace)}>
                    Kick
                  </button>
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={() => {
                      if (confirm(`Ban ${m.username}? They won't be able to rejoin until unbanned.`)) {
                        void run(() => act({ kind: 'ban', spaceId, userId: m.userId }), setSpace);
                      }
                    }}
                  >
                    Ban
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>

        {space.bans && space.bans.length > 0 && (
          <>
            <div className="sidebar-title">Banned</div>
            <ul>
              {space.bans.map((b) => (
                <li key={b.userId} className="member">
                  <div>{b.username}</div>
                  <button disabled={busy} onClick={() => void run(() => act({ kind: 'unban', spaceId, userId: b.userId }), setSpace)}>
                    Unban
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}

        {manager && (
          <div className="invite">
            <button disabled={busy} onClick={() => void run(() => act({ kind: 'createInvite', spaceId }), setInvite)}>
              Create invite
            </button>
            {invite && (
              <p className="muted">
                Share this code. It works {invite.maxUses} times and expires {new Date(invite.expiresAt).toLocaleString()}.
                <code className="block" data-testid="space-invite">{invite.code}</code>
              </p>
            )}
          </div>
        )}

        <div className="row">
          {space.role === 'owner' ? (
            <button
              className="danger"
              disabled={busy}
              onClick={() => {
                if (confirm(`Delete ${space.name} for everyone? This can't be undone.`)) void run(() => act({ kind: 'delete', spaceId }), onGone);
              }}
            >
              Delete server
            </button>
          ) : (
            <button disabled={busy} onClick={() => void run(() => act({ kind: 'leave', spaceId }), onGone)}>
              Leave server
            </button>
          )}
        </div>
      </section>
    </div>
  );
}
