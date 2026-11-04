import { useEffect, useRef, useState } from 'react';
import type { Conversation } from '../shared/ipc';
import { BlockButton, SafetyNumber } from './Safety';

export function DmPage({ peerUserId, peerUsername, onSent }: { peerUserId: string; peerUsername?: string; onSent: () => void }) {
  const [conv, setConv] = useState<Conversation>();
  const [text, setText] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const load = async () => {
      const r = await window.silo.dm({ kind: 'get', peerUserId, peerUsername });
      if (r.ok) setConv(r.value);
      else setError(r.error);
    };
    void load();
    const off = window.silo.onEvent((e) => {
      if (e.type === 'messages' && e.peerUserId === peerUserId) void load();
    });
    return () => {
      off();
    };
  }, [peerUserId, peerUsername]);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' });
  }, [conv?.messages.length]);

  async function send() {
    if (!conv || !text.trim()) return;
    setBusy(true);
    setError(undefined);
    const r = await window.silo.dm({ kind: 'send', peerUserId, peerUsername: conv.peerUsername, text });
    setBusy(false);
    if (r.ok) {
      setConv(r.value);
      setText('');
      onSent();
    } else setError(r.error);
  }

  // The newest message tells us whether the last thing they sent was blocked for a changed key.
  const lastFromThem = conv?.messages.filter((m) => m.from === 'them').at(-1);
  const keyChanged = !!lastFromThem?.error?.includes('encryption key changed');

  return (
    <section className="chat" aria-label={`Messages with ${conv?.peerUsername ?? ''}`}>
      <header className="chat-header">
        <h1>{conv?.peerUsername ?? peerUsername ?? '…'}</h1>
        <span className="muted">End-to-end encrypted. Only you and {conv?.peerUsername ?? 'them'} can read these.</span>
        <div className="chat-tools">
          <SafetyNumber
            peerUserId={peerUserId}
            peerUsername={conv?.peerUsername ?? peerUsername ?? 'them'}
            keyChanged={keyChanged}
          />
          <BlockButton userId={peerUserId} username={conv?.peerUsername ?? peerUsername ?? 'them'} />
        </div>
      </header>
      <ol className="messages" data-testid="messages">
        {conv?.messages.map((m) => (
          <li key={m.id} className={`msg ${m.from}${m.error ? ' failed' : ''}`}>
            <div className="msg-meta">
              {m.from === 'me' ? 'You' : conv.peerUsername} · {new Date(m.sentAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </div>
            <div className="msg-text">{m.error ?? m.text}</div>
            {m.note && <div className="msg-note">{m.note}</div>}
          </li>
        ))}
        {conv && conv.messages.length === 0 && <li className="muted">No messages yet. Say hello.</li>}
      </ol>
      <div ref={bottom} />
      {error && <div className="error">{error}</div>}
      <form
        className="composer"
        onSubmit={(e) => {
          e.preventDefault();
          void send();
        }}
      >
        <textarea
          aria-label="Message"
          value={text}
          maxLength={4000}
          rows={2}
          placeholder={`Message ${conv?.peerUsername ?? ''}`}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault();
              void send();
            }
          }}
        />
        <button className="primary" type="submit" disabled={busy || !text.trim()}>
          Send
        </button>
      </form>
    </section>
  );
}
