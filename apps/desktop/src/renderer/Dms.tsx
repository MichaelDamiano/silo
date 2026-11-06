import { useEffect, useRef, useState } from 'react';
import type { Conversation, DmMessage } from '../shared/ipc';
import { ForwardDialog, ForwardedLabel, MessageTools, Reactions, ReplyingBar, ReplyQuote } from './Message';
import { BlockButton, SafetyNumber } from './Safety';

export function DmPage({ peerUserId, peerUsername, onSent }: { peerUserId: string; peerUsername?: string; onSent: () => void }) {
  const [conv, setConv] = useState<Conversation>();
  const [text, setText] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [replyTo, setReplyTo] = useState<DmMessage>();
  const [forwarding, setForwarding] = useState<string>();
  const input = useRef<HTMLTextAreaElement>(null);
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
    const r = await window.silo.dm({ kind: 'send', peerUserId, peerUsername: conv.peerUsername, text, replyTo: replyTo?.id });
    setBusy(false);
    if (r.ok) {
      setConv(r.value);
      setText('');
      setReplyTo(undefined);
      onSent();
    } else setError(r.error);
  }

  async function react(messageId: string, emoji: string, on: boolean) {
    if (!conv) return;
    setError(undefined);
    const r = await window.silo.dm({ kind: 'react', peerUserId, peerUsername: conv.peerUsername, messageId, emoji, on });
    if (r.ok) setConv(r.value);
    else setError(r.error);
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
              {!m.error && (
                <MessageTools
                  onReply={() => {
                    setReplyTo(m);
                    input.current?.focus();
                  }}
                  onReact={(emoji) => void react(m.id, emoji, !m.reactions?.some((r) => r.emoji === emoji && r.mine))}
                  onForward={() => setForwarding(m.text)}
                />
              )}
            </div>
            {m.replyTo && <ReplyQuote reply={m.replyTo} />}
            {m.forwarded && <ForwardedLabel />}
            <div className="msg-text">{m.error ?? m.text}</div>
            <Reactions reactions={m.reactions} onToggle={(emoji, on) => void react(m.id, emoji, on)} />
            {m.note && <div className="msg-note">{m.note}</div>}
          </li>
        ))}
        {conv && conv.messages.length === 0 && <li className="muted">No messages yet. Say hello.</li>}
      </ol>
      <div ref={bottom} />
      {error && <div className="error">{error}</div>}
      {replyTo && (
        <ReplyingBar author={replyTo.from === 'me' ? 'yourself' : (conv?.peerUsername ?? 'them')} text={replyTo.text} onCancel={() => setReplyTo(undefined)} />
      )}
      {forwarding !== undefined && <ForwardDialog text={forwarding} onClose={() => setForwarding(undefined)} />}
      <form
        className="composer"
        onSubmit={(e) => {
          e.preventDefault();
          void send();
        }}
      >
        <textarea
          ref={input}
          aria-label="Message"
          value={text}
          maxLength={4000}
          rows={2}
          placeholder={`Message ${conv?.peerUsername ?? ''}`}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') setReplyTo(undefined);
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
