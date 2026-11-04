import { useEffect, useRef, useState } from 'react';
import type { ChannelView } from '../shared/ipc';
import { ReportForm } from './Safety';

export function ChannelPage({ spaceId, channelId, name }: { spaceId: string; channelId: string; name: string }) {
  const [view, setView] = useState<ChannelView>();
  const [text, setText] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [reporting, setReporting] = useState<string>();
  const [shown, setShown] = useState<Set<string>>(new Set());
  const bottom = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setView(undefined);
    setError(undefined);
    const load = async () => {
      const r = await window.silo.channel({ kind: 'get', spaceId, channelId });
      if (r.ok) setView(r.value);
      else setError(r.error);
    };
    void load();
    const off = window.silo.onEvent((e) => {
      if (e.type === 'channel' && e.channelId === channelId) void load();
    });
    return () => {
      off();
    };
  }, [spaceId, channelId]);

  useEffect(() => {
    bottom.current?.scrollIntoView({ block: 'end' });
  }, [view?.messages.length]);

  async function send() {
    if (!text.trim()) return;
    setBusy(true);
    setError(undefined);
    const r = await window.silo.channel({ kind: 'send', spaceId, channelId, text });
    setBusy(false);
    if (r.ok) {
      setView(r.value);
      setText('');
    } else setError(r.error);
  }

  return (
    <section className="chat" aria-label={`Messages in #${name}`}>
      <header className="chat-header">
        <h1># {name}</h1>
        <span className="muted">End-to-end encrypted. Only members of this server can read these.</span>
      </header>
      <ol className="messages" data-testid="messages">
        {view?.messages.map((m) =>
          m.blocked && !shown.has(m.id) ? (
            <li key={m.id} className="msg them hidden-msg">
              <span className="muted">Message from someone you blocked.</span>
              <button className="link" onClick={() => setShown(new Set(shown).add(m.id))}>
                Show
              </button>
            </li>
          ) : (
            <li key={m.id} className={`msg ${m.from}${m.error ? ' failed' : ''}`}>
              <div className="msg-meta">
                {m.from === 'me' ? 'You' : m.senderUsername} · {new Date(m.sentAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                {m.from === 'them' && m.seq && (
                  <button className="link" onClick={() => setReporting(reporting === m.id ? undefined : m.id)} data-testid="report-message">
                    Report
                  </button>
                )}
              </div>
              <div className="msg-text">{m.error ?? m.text}</div>
              {m.note && <div className="msg-note">{m.note}</div>}
              {reporting === m.id && (
                <ReportForm
                  what={`this message from ${m.senderUsername}`}
                  send={async (reason, note) => {
                    const r = await window.silo.safety({ kind: 'reportMessage', spaceId, channelId, messageId: m.id, reason, note });
                    if (!r.ok) throw new Error(r.error);
                  }}
                  onDone={() => setReporting(undefined)}
                />
              )}
            </li>
          ),
        )}
        {view && view.messages.length === 0 && <li className="muted">No messages yet. Start the conversation.</li>}
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
          placeholder={`Message #${name}`}
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
