import { useEffect, useState } from 'react';
import type { ReportReason, ReportView, SafetyAction, SafetyResult, SafetyView } from '../shared/ipc';

async function act<A extends SafetyAction>(action: A): Promise<SafetyResult<A>> {
  const r = await window.silo.safety(action);
  if (!r.ok) throw new Error(r.error);
  return r.value;
}

export const REASONS: { value: ReportReason; label: string }[] = [
  { value: 'spam', label: 'Spam' },
  { value: 'scam', label: 'Scam or fraud' },
  { value: 'harassment', label: 'Harassment' },
  { value: 'malware', label: 'Malware or a dangerous link' },
  { value: 'illegal', label: 'Illegal content' },
  { value: 'other', label: 'Something else' },
];

const STATUS: Record<SafetyView['status'], string> = {
  verified: 'Verified',
  unverified: 'Not verified',
  changed: 'Safety number changed',
  incomplete: 'Not verified',
};

/**
 * The safety number for a conversation. Two people read it to each other in
 * person or on a call; if it matches, nobody (not even the server) is in between.
 */
export function SafetyNumber({ peerUserId, peerUsername, keyChanged }: { peerUserId: string; peerUsername: string; keyChanged: boolean }) {
  const [view, setView] = useState<SafetyView>();
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  const load = () => act({ kind: 'safetyNumber', peerUserId }).then(setView, (e: Error) => setError(e.message));
  useEffect(() => {
    setView(undefined);
    void load();
  }, [peerUserId]);

  async function run(action: Extract<SafetyAction, { kind: 'verify' | 'unverify' | 'acceptNewKeys' }>) {
    setBusy(true);
    setError(undefined);
    try {
      setView((await act(action)) as unknown as SafetyView);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const status = view?.status;
  const warn = status === 'changed' || keyChanged;
  return (
    <div className="safety" data-testid="safety">
      <button
        className={`link ${warn ? 'warn' : ''}`}
        onClick={() => {
          // Devices and keys may have changed since the conversation opened.
          if (!open) void load();
          setOpen(!open);
        }}
        data-testid="safety-toggle"
      >
        {keyChanged ? 'Encryption key changed' : status ? STATUS[status] : 'Safety number'}
        {status === 'verified' && ' ✓'}
      </button>
      {open && (
        <div className="safety-panel">
          {keyChanged && (
            <p className="error">
              One of {peerUsername}’s devices showed up with a different encryption key. The
              server never changes keys on its own, so this means they reinstalled, or someone is trying to read your messages. Messages
              with them are blocked until you check with them, outside Silo, and accept the new key.
            </p>
          )}
          {!keyChanged && status === 'changed' && (
            <p className="error">
              This number no longer matches the one you verified. {peerUsername} or you added a device, or a key was replaced. Compare
              again before sharing anything sensitive.
            </p>
          )}
          {view?.number ? (
            <>
              <p className="muted">
                Compare this with {peerUsername} in person or on a call. If it matches on both screens, nobody is in between. It covers{' '}
                {view.theirDevices === 1 ? '1 of their devices' : `${view.theirDevices} of their devices`} and{' '}
                {view.myDevices === 1 ? '1 of yours' : `${view.myDevices} of yours`}.
              </p>
              <code className="block safety-digits" data-testid="safety-number">
                {view.number}
              </code>
            </>
          ) : (
            view && (
              <p className="muted">
                No number yet. Each of you needs to send the other a message first, so both apps have the keys for every device.
              </p>
            )
          )}
          <div className="row">
            {view?.number && status !== 'verified' && !keyChanged && (
              <button disabled={busy} onClick={() => void run({ kind: 'verify', peerUserId, number: view.number! })}>
                It matches, mark as verified
              </button>
            )}
            {status === 'verified' && (
              <button disabled={busy} onClick={() => void run({ kind: 'unverify', peerUserId })}>
                Clear verification
              </button>
            )}
            {keyChanged && (
              <button
                className="danger"
                disabled={busy}
                onClick={() => {
                  if (confirm(`Only do this if ${peerUsername} told you, outside Silo, that they reinstalled or replaced a device. Accept the new key?`)) {
                    void run({ kind: 'acceptNewKeys', peerUserId });
                  }
                }}
              >
                I checked with them, accept the new key
              </button>
            )}
          </div>
          {error && <div className="error">{error}</div>}
        </div>
      )}
    </div>
  );
}

export function BlockButton({ userId, username, onChange }: { userId: string; username: string; onChange?: (blocked: boolean) => void }) {
  const [blocked, setBlocked] = useState<boolean>();
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    act({ kind: 'blocks' }).then((list) => setBlocked(list.some((b) => b.userId === userId)), () => setBlocked(false));
  }, [userId]);
  if (blocked === undefined) return null;
  return (
    <button
      className={blocked ? '' : 'danger'}
      disabled={busy}
      data-testid="block-toggle"
      onClick={async () => {
        if (!blocked && !confirm(`Block ${username}? You won't get their direct messages, and their channel messages will be hidden. They aren't told.`)) return;
        setBusy(true);
        try {
          const list = await act(blocked ? { kind: 'unblock', userId } : { kind: 'block', userId });
          const now = list.some((b) => b.userId === userId);
          setBlocked(now);
          onChange?.(now);
        } catch (e) {
          alert((e as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      {blocked ? 'Unblock' : 'Block'}
    </button>
  );
}

/** Asks why, then sends a report to the server's moderators. */
export function ReportForm({
  what,
  send,
  onDone,
}: {
  what: string;
  send: (reason: ReportReason, note: string) => Promise<unknown>;
  onDone: () => void;
}) {
  const [reason, setReason] = useState<ReportReason>('spam');
  const [note, setNote] = useState('');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  if (sent)
    return (
      <div className="report-form" data-testid="report-sent">
        <p className="muted">Reported. The server’s moderators will see it.</p>
        <button onClick={onDone}>Close</button>
      </div>
    );
  return (
    <form
      className="report-form"
      data-testid="report-form"
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(undefined);
        try {
          await send(reason, note);
          setSent(true);
        } catch (err) {
          setError((err as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <p className="muted">
        Report {what} to this server’s owner and admins. Messages are end-to-end encrypted, so the report includes the text as you see it.
      </p>
      <select aria-label="Reason" value={reason} onChange={(e) => setReason(e.target.value as ReportReason)}>
        {REASONS.map((r) => (
          <option key={r.value} value={r.value}>
            {r.label}
          </option>
        ))}
      </select>
      <input aria-label="Details" placeholder="Details (optional)" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />
      <div className="row">
        <button className="primary" type="submit" disabled={busy}>
          Send report
        </button>
        <button type="button" onClick={onDone}>
          Cancel
        </button>
      </div>
      {error && <div className="error">{error}</div>}
    </form>
  );
}

const CHECK: Record<NonNullable<ReportView['localCopy']>, string> = {
  matches: 'Matches your copy of the message.',
  differs: 'Does NOT match your copy. The reporter may have changed it.',
  unavailable: 'You can’t see this message yourself, so the text can’t be checked.',
};

/** The report queue for a server's owner and admins. */
export function ReportsPanel({
  spaceId,
  onBan,
  onClose,
}: {
  spaceId: string;
  onBan: (userId: string, username: string) => Promise<void>;
  onClose: () => void;
}) {
  const [closed, setClosed] = useState(false);
  const [reports, setReports] = useState<ReportView[]>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const load = () => act({ kind: 'reports', spaceId, closed }).then(setReports, (e: Error) => setError(e.message));
  useEffect(() => {
    setReports(undefined);
    void load();
  }, [spaceId, closed]);

  async function resolve(reportId: string, status: 'resolved' | 'dismissed') {
    setBusy(true);
    setError(undefined);
    try {
      setReports(await act({ kind: 'resolveReport', spaceId, reportId, status }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="chat reports" aria-label="Reports" data-testid="reports">
      <header className="chat-header">
        <h1>Reports</h1>
        <div className="row">
          <button className="link" onClick={() => setClosed(!closed)}>
            {closed ? 'Show open' : 'Show handled'}
          </button>
          <button className="link" onClick={onClose}>
            Back to channels
          </button>
        </div>
      </header>
      {error && <div className="error">{error}</div>}
      <ol className="report-list">
        {reports?.map((r) => (
          <li key={r.id} className="report" data-testid="report">
            <div className="msg-meta">
              {REASONS.find((x) => x.value === r.reason)?.label} · {r.reported.username}
              {!r.reported.isMember && ' (no longer a member)'}
              {r.channelName && ` in #${r.channelName}`} · reported by {r.reporter?.username ?? 'a deleted account'} ·{' '}
              {new Date(r.createdAt).toLocaleString()}
            </div>
            {r.excerpt && <div className="msg-text">{r.excerpt}</div>}
            {r.localCopy && (
              <div className={`report-check ${r.localCopy}`} data-testid="report-check">
                {CHECK[r.localCopy]}
              </div>
            )}
            {r.localCopy === 'differs' && r.localText !== undefined && <div className="msg-text">Your copy: {r.localText}</div>}
            {r.note && <div className="muted">“{r.note}”</div>}
            {r.status === 'open' ? (
              <div className="row">
                {r.reported.isMember && (
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={async () => {
                      if (!confirm(`Ban ${r.reported.username} from this server?`)) return;
                      setBusy(true);
                      try {
                        await onBan(r.reported.userId, r.reported.username);
                        await act({ kind: 'resolveReport', spaceId, reportId: r.id, status: 'resolved' }).then(setReports);
                      } catch (e) {
                        setError((e as Error).message);
                      } finally {
                        setBusy(false);
                      }
                    }}
                  >
                    Ban {r.reported.username}
                  </button>
                )}
                <button disabled={busy} onClick={() => void resolve(r.id, 'resolved')}>
                  Mark handled
                </button>
                <button disabled={busy} onClick={() => void resolve(r.id, 'dismissed')}>
                  Dismiss
                </button>
              </div>
            ) : (
              <div className="muted">{r.status === 'resolved' ? 'Handled' : 'Dismissed'}</div>
            )}
          </li>
        ))}
        {reports && reports.length === 0 && <li className="muted">{closed ? 'Nothing handled yet.' : 'No open reports.'}</li>}
      </ol>
    </section>
  );
}
