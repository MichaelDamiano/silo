import { useEffect, useState, type ReactNode } from 'react';
import type { ReactionView, ReplyView } from '../shared/ipc';

/** The quick picks offered when reacting. Any single emoji is accepted by the protocol. */
export const QUICK_EMOJI = ['👍', '❤️', '😂', '😮', '😢', '🎉', '👀', '✅'];

/** The message a reply answers, shown above it. */
export function ReplyQuote({ reply }: { reply: ReplyView }) {
  return (
    <div className="reply-quote" data-testid="reply-quote">
      <span className="reply-author">{reply.author}</span>
      <span className="reply-text">{reply.text}</span>
      {reply.missing && (
        <span className="reply-missing" title="The original isn’t on this device, so this quote is only what the sender says it was.">
          (original not on this device)
        </span>
      )}
    </div>
  );
}

export function ForwardedLabel() {
  return (
    <div className="forwarded" data-testid="forwarded" title="Copied from another conversation. Be careful with forwarded links and requests.">
      ↪ Forwarded
    </div>
  );
}

/** The emoji under a message. Clicking one adds yours, or takes it back if it's already yours. */
export function Reactions({ reactions, onToggle }: { reactions?: ReactionView[]; onToggle: (emoji: string, on: boolean) => void }) {
  if (!reactions?.length) return null;
  return (
    <div className="reactions" data-testid="reactions">
      {reactions.map((r) => (
        <button
          key={r.emoji}
          className={`reaction${r.mine ? ' mine' : ''}`}
          title={r.names.join(', ')}
          aria-pressed={r.mine}
          onClick={() => onToggle(r.emoji, !r.mine)}
        >
          {r.emoji} {r.count}
        </button>
      ))}
    </div>
  );
}

/** Reply, react and forward links shown with each readable message. */
export function MessageTools({
  onReply,
  onReact,
  onForward,
  children,
}: {
  onReply: () => void;
  onReact: (emoji: string) => void;
  onForward: () => void;
  children?: ReactNode;
}) {
  const [picking, setPicking] = useState(false);
  return (
    <span className="msg-tools">
      <button className="link" onClick={onReply} data-testid="reply">
        Reply
      </button>
      <button className="link" onClick={() => setPicking(!picking)} aria-expanded={picking} data-testid="react">
        React
      </button>
      <button className="link" onClick={onForward} data-testid="forward">
        Forward
      </button>
      {children}
      {picking && (
        <span className="emoji-palette" role="menu">
          {QUICK_EMOJI.map((e) => (
            <button
              key={e}
              role="menuitem"
              aria-label={`React with ${e}`}
              onClick={() => {
                setPicking(false);
                onReact(e);
              }}
            >
              {e}
            </button>
          ))}
        </span>
      )}
    </span>
  );
}

/** Above the composer while writing a reply. */
export function ReplyingBar({ author, text, onCancel }: { author: string; text: string; onCancel: () => void }) {
  return (
    <div className="replying" data-testid="replying">
      <span className="muted">
        Replying to <strong>{author}</strong>: {text.length > 80 ? text.slice(0, 80) + '…' : text}
      </span>
      <button className="icon" aria-label="Cancel reply" onClick={onCancel}>
        ×
      </button>
    </div>
  );
}

type Destination =
  | { kind: 'dm'; key: string; label: string; peerUserId: string; peerUsername: string }
  | { kind: 'channel'; key: string; label: string; spaceId: string; channelId: string };

/**
 * Picks a conversation or channel to forward a message to. The copy is encrypted for
 * its new destination like any other message, and only says that it was forwarded.
 */
export function ForwardDialog({ text, onClose }: { text: string; onClose: () => void }) {
  const [dests, setDests] = useState<Destination[]>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string>();

  useEffect(() => {
    void (async () => {
      const out: Destination[] = [];
      const dms = await window.silo.dm({ kind: 'list' });
      if (dms.ok) {
        for (const c of dms.value) {
          out.push({ kind: 'dm', key: `dm-${c.peerUserId}`, label: c.peerUsername, peerUserId: c.peerUserId, peerUsername: c.peerUsername });
        }
      }
      const spaces = await window.silo.space({ kind: 'list' });
      if (spaces.ok) {
        for (const s of spaces.value) {
          const v = await window.silo.space({ kind: 'get', spaceId: s.id });
          if (!v.ok) continue;
          for (const c of v.value.channels) {
            out.push({ kind: 'channel', key: `ch-${c.id}`, label: `${s.name} › #${c.name}`, spaceId: s.id, channelId: c.id });
          }
        }
      }
      setDests(out);
    })();
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function forward(d: Destination) {
    setBusy(true);
    setError(undefined);
    const r =
      d.kind === 'dm'
        ? await window.silo.dm({ kind: 'send', peerUserId: d.peerUserId, peerUsername: d.peerUsername, text, forwarded: true })
        : await window.silo.channel({ kind: 'send', spaceId: d.spaceId, channelId: d.channelId, text, forwarded: true });
    setBusy(false);
    if (r.ok) setDone(d.label);
    else setError(r.error);
  }

  return (
    <div className="overlay" onClick={onClose}>
      <div className="dialog" role="dialog" aria-label="Forward message" onClick={(e) => e.stopPropagation()} data-testid="forward-dialog">
        <h2>Forward message</h2>
        <p className="forward-preview">{text.length > 200 ? text.slice(0, 200) + '…' : text}</p>
        {done ? (
          <>
            <p>Forwarded to {done}.</p>
            <div className="row">
              <button className="primary" onClick={onClose}>
                Done
              </button>
            </div>
          </>
        ) : (
          <>
            {!dests && <p className="muted">Loading conversations…</p>}
            {dests && dests.length === 0 && <p className="muted">There’s nowhere to forward to yet.</p>}
            <ul className="forward-list">
              {dests?.map((d) => (
                <li key={d.key}>
                  <button className="nav" disabled={busy} onClick={() => void forward(d)}>
                    {d.kind === 'dm' ? '@ ' : ''}
                    {d.label}
                  </button>
                </li>
              ))}
            </ul>
            {error && <div className="error">{error}</div>}
            <div className="row">
              <button onClick={onClose}>Cancel</button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
