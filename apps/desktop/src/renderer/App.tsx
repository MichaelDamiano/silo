import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react';
import type { AccountView, ConversationSummary, DeviceInfo, LinkTicket, PendingDevice, Result, SpaceSummary } from '../shared/ipc';
import { DmPage } from './Dms';
import { ConnectionSettings } from './Connection';
import { NewSpace, Sidebar, SpacePage } from './Spaces';

type Mode = 'signup' | 'login' | 'link' | 'recover';

const DEFAULT_SERVER = 'http://localhost:8443';

export function App() {
  const [device, setDevice] = useState<DeviceInfo>();
  const [account, setAccount] = useState<AccountView>();
  const [recoveryKey, setRecoveryKey] = useState<string>();
  const [ticket, setTicket] = useState<LinkTicket>();

  useEffect(() => {
    void window.silo.deviceInfo().then(setDevice);
  }, []);

  if (recoveryKey) return <RecoveryKeyScreen recoveryKey={recoveryKey} onDone={() => setRecoveryKey(undefined)} />;
  if (account) return <Home account={account} onChange={setAccount} onRecoveryKey={setRecoveryKey} onSignedOut={() => setAccount(undefined)} />;
  if (ticket) {
    return (
      <WaitingForApproval
        ticket={ticket}
        onApproved={setAccount}
        onCancel={() => setTicket(undefined)}
      />
    );
  }

  return (
    <Panel title="Silo" subtitle="Your account is tied to keys stored on this device. No email or phone number needed.">
      {device && !device.secureStorage && (
        <div className="warning">
          No system keychain was found, so this device's key can't be stored safely. Sign-in is disabled until one is installed.
        </div>
      )}
      <AuthForm
        disabled={!device?.secureStorage}
        onSignedIn={(a, key) => {
          setAccount(a);
          if (key) setRecoveryKey(key);
        }}
        onWaiting={setTicket}
      />
      {device?.fingerprint && <p className="muted">This device's fingerprint: <code>{device.fingerprint}</code></p>}
    </Panel>
  );
}

function Panel({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main>
      <div className="panel">
        <h1>{title}</h1>
        {subtitle && <p className="muted">{subtitle}</p>}
        {children}
      </div>
    </main>
  );
}

function useAction() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function run<T>(fn: () => Promise<Result<T>>, onOk: (v: T) => void) {
    setBusy(true);
    setError(undefined);
    const result = await fn();
    setBusy(false);
    if (result.ok) onOk(result.value);
    else setError(result.error);
  }
  return { busy, error, run, setError };
}

function AuthForm({
  onSignedIn,
  onWaiting,
  disabled,
}: {
  onSignedIn: (a: AccountView, recoveryKey?: string) => void;
  onWaiting: (t: LinkTicket) => void;
  disabled: boolean;
}) {
  const [mode, setMode] = useState<Mode>('signup');
  const [serverUrl, setServerUrl] = useState(DEFAULT_SERVER);
  const [inviteCode, setInviteCode] = useState('');
  const [username, setUsername] = useState('');
  const [deviceName, setDeviceName] = useState('My computer');
  const [recoveryKey, setRecoveryKey] = useState('');
  const { busy, error, run } = useAction();

  function submit(e: FormEvent) {
    e.preventDefault();
    if (mode === 'signup') {
      void run(() => window.silo.signup({ serverUrl, inviteCode, username, deviceName }), (v) => onSignedIn(v.account, v.recoveryKey));
    } else if (mode === 'login') {
      void run(() => window.silo.login({ serverUrl }), (a) => onSignedIn(a));
    } else if (mode === 'link') {
      void run(() => window.silo.requestLink({ serverUrl, username, deviceName }), onWaiting);
    } else {
      void run(() => window.silo.recover({ serverUrl, username, recoveryKey, deviceName }), (v) => onSignedIn(v.account, v.recoveryKey));
    }
  }

  const tab = (m: Mode, label: string) => (
    <button type="button" aria-pressed={mode === m} onClick={() => setMode(m)}>
      {label}
    </button>
  );
  const submitLabel = { signup: 'Create account', login: 'Log in', link: 'Ask to join', recover: 'Recover account' }[mode];

  return (
    <>
    <form onSubmit={submit}>
      <div className="tabs">
        {tab('signup', 'Join with invite')}
        {tab('login', 'Log in')}
        {tab('link', 'Add this device')}
        {tab('recover', 'Recover')}
      </div>
      {mode === 'link' && <p className="muted">Ask to add this device to an account you already have. You'll approve it from a device that's signed in.</p>}
      {mode === 'recover' && (
        <p className="muted">Lost all your devices? Your recovery key signs you in here and signs out every other device.</p>
      )}
      <label htmlFor="server">Server address</label>
      <input id="server" value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} required />
      {mode === 'signup' && (
        <>
          <label htmlFor="invite">Invite</label>
          <input
            id="invite"
            value={inviteCode}
            onChange={(e) => {
              setInviteCode(e.target.value);
              // A full invite names the server, so fill in its address too.
              const address = /^silo:[^:]+:[^:]+:(https?:\/\/.+)$/.exec(e.target.value.trim())?.[1];
              if (address) setServerUrl(address);
            }}
            required
            autoComplete="off"
          />
          {inviteCode.trim() && !inviteCode.trim().startsWith('silo:') && (
            <p className="muted">
              This is a bare code, without the server’s key. Silo will trust whichever server answers at this address the first time. A full
              invite starts with silo: and checks the server for you.
            </p>
          )}
        </>
      )}
      {mode !== 'login' && (
        <>
          <label htmlFor="username">Username</label>
          <input id="username" value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} required pattern="[a-z0-9_]{3,32}" />
        </>
      )}
      {mode === 'recover' && (
        <>
          <label htmlFor="recovery">Recovery key</label>
          <input id="recovery" value={recoveryKey} onChange={(e) => setRecoveryKey(e.target.value)} required autoComplete="off" spellCheck={false} />
        </>
      )}
      {mode !== 'login' && (
        <>
          <label htmlFor="device">Name for this device</label>
          <input id="device" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} required maxLength={64} />
        </>
      )}
      {error && <div className="error">{error}</div>}
      <div className="row">
        <button className="primary" type="submit" disabled={busy || disabled}>
          {submitLabel}
        </button>
      </div>
    </form>
    <details className="advanced">
      <summary>Tor settings</summary>
      <ConnectionSettings signedIn={false} />
    </details>
    </>
  );
}

function RecoveryKeyScreen({ recoveryKey, onDone }: { recoveryKey: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  return (
    <Panel title="Save your recovery key" subtitle="If you lose every device, this key is the only way back into your account. It's shown once and isn't stored anywhere.">
      <pre className="recovery-key" data-testid="recovery-key">{recoveryKey}</pre>
      <p className="muted">Write it down or keep it in a password manager. Anyone who has it can take over your account.</p>
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} /> I've saved my recovery key
      </label>
      <div className="row">
        <button className="primary" disabled={!saved} onClick={onDone}>
          Continue
        </button>
      </div>
    </Panel>
  );
}

function WaitingForApproval({ ticket, onApproved, onCancel }: { ticket: LinkTicket; onApproved: (a: AccountView) => void; onCancel: () => void }) {
  const [error, setError] = useState<string>();
  const done = useRef(false);

  useEffect(() => {
    const expires = Date.parse(ticket.expiresAt);
    const timer = setInterval(async () => {
      if (done.current) return;
      if (Date.now() > expires) {
        setError('The code expired. Go back and ask again.');
        clearInterval(timer);
        return;
      }
      const result = await window.silo.checkLink();
      if (result.ok && result.value) {
        done.current = true;
        clearInterval(timer);
        onApproved(result.value);
      } else if (!result.ok) {
        setError(result.error);
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [ticket, onApproved]);

  return (
    <Panel title="Approve this device" subtitle="On a device that's already signed in, choose Approve a new device and enter this code.">
      <pre className="pairing-code" data-testid="pairing-code">{ticket.pairingCode}</pre>
      <p className="muted">
        Check that the other device shows this fingerprint before approving: <code>{ticket.fingerprint}</code>
      </p>
      <p className="muted">Waiting for approval. The code expires in 10 minutes.</p>
      {error && <div className="error">{error}</div>}
      <div className="row">
        <button onClick={onCancel}>Back</button>
      </div>
    </Panel>
  );
}

type View = { kind: 'account' } | { kind: 'new' } | { kind: 'space'; id: string } | { kind: 'dm'; peerUserId: string; peerUsername: string };

function Home(props: {
  account: AccountView;
  onChange: (a: AccountView) => void;
  onRecoveryKey: (key: string) => void;
  onSignedOut: () => void;
}) {
  const [spaces, setSpaces] = useState<SpaceSummary[]>([]);
  const [view, setView] = useState<View>({ kind: 'account' });
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [notice, setNotice] = useState<string>();

  async function refreshDms() {
    const r = await window.silo.dm({ kind: 'list' });
    if (r.ok) setConversations(r.value);
  }

  useEffect(() => {
    void refreshDms();
    const off = window.silo.onEvent((e) => {
      if (e.type === 'messages') void refreshDms();
      else if (e.type === 'error') setNotice(e.message);
    });
    return () => {
      off();
    };
  }, []);

  async function refresh(select?: View) {
    const result = await window.silo.space({ kind: 'list' });
    if (result.ok) {
      setSpaces(result.value);
      if (select) setView(select);
      else if (result.value[0] && view.kind === 'account') setView({ kind: 'space', id: result.value[0].id });
    }
  }

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="shell">
      <Sidebar
        spaces={spaces}
        selected={view.kind === 'space' ? view.id : view.kind === 'new' ? 'new' : undefined}
        accountSelected={view.kind === 'account'}
        onSelect={(id) => setView(id === 'new' ? { kind: 'new' } : { kind: 'space', id })}
        onAccount={() => setView({ kind: 'account' })}
        conversations={conversations}
        selectedDm={view.kind === 'dm' ? view.peerUserId : undefined}
        onSelectDm={(c) => setView({ kind: 'dm', peerUserId: c.peerUserId, peerUsername: c.peerUsername })}
      />
      {view.kind === 'new' && <NewSpace onDone={(s) => void refresh({ kind: 'space', id: s.id })} />}
      {view.kind === 'space' && (
        <SpacePage
          key={view.id}
          spaceId={view.id}
          myUsername={props.account.username}
          onGone={() => void refresh({ kind: 'new' })}
          onMessage={(peerUserId, peerUsername) => setView({ kind: 'dm', peerUserId, peerUsername })}
        />
      )}
      {view.kind === 'dm' && (
        <DmPage key={view.peerUserId} peerUserId={view.peerUserId} peerUsername={view.peerUsername} onSent={() => void refreshDms()} />
      )}
      {notice && (
        <div className="toast" role="alert">
          {notice} <button className="link" onClick={() => setNotice(undefined)}>Dismiss</button>
        </div>
      )}
      {view.kind === 'account' && (
        <div className="content">
          <AccountScreen {...props} />
        </div>
      )}
    </div>
  );
}

function AccountScreen({
  account,
  onChange,
  onRecoveryKey,
  onSignedOut,
}: {
  account: AccountView;
  onChange: (a: AccountView) => void;
  onRecoveryKey: (key: string) => void;
  onSignedOut: () => void;
}) {
  const [pairingCode, setPairingCode] = useState('');
  const [pending, setPending] = useState<PendingDevice>();
  const [accountInvite, setAccountInvite] = useState<{ code: string; expiresAt: string }>();
  const { busy, error, run } = useAction();

  return (
    <div>
      <h1>Signed in as {account.username}</h1>
      <p className="muted">These devices can sign in to your account. Revoke any you don't recognise.</p>
      <ul className="devices">
        {account.devices.map((d) => (
          <li key={d.id}>
            <div>
              {d.name} {d.current && <span className="muted">(this device)</span>} {d.revoked && <span className="muted">(revoked)</span>}
              <div className="muted"><code>{d.fingerprint}</code></div>
            </div>
            {!d.revoked && !d.current && (
              <button disabled={busy} onClick={() => void run(() => window.silo.revokeDevice({ deviceId: d.id }), onChange)}>
                Revoke
              </button>
            )}
          </li>
        ))}
      </ul>

      <h2>Approve a new device</h2>
      {!pending ? (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => window.silo.lookupLink({ pairingCode }), setPending);
          }}
        >
          <label htmlFor="pairing">Code shown on the new device</label>
          <input id="pairing" value={pairingCode} onChange={(e) => setPairingCode(e.target.value)} required autoComplete="off" spellCheck={false} />
          <div className="row">
            <button type="submit" disabled={busy}>Find device</button>
          </div>
        </form>
      ) : (
        <div className="confirm" data-testid="pending-device">
          <p>
            <strong>{pending.deviceName}</strong> wants to join your account.
          </p>
          <p className="muted">
            Only approve if the new device shows this exact fingerprint: <code>{pending.fingerprint}</code>
          </p>
          <div className="row">
            <button
              className="primary"
              disabled={busy}
              onClick={() =>
                void run(() => window.silo.approveLink(), (a) => {
                  setPending(undefined);
                  setPairingCode('');
                  onChange(a);
                })
              }
            >
              Fingerprints match, approve
            </button>
            <button onClick={() => setPending(undefined)}>Cancel</button>
          </div>
        </div>
      )}

      <h2>Invite someone to Silo</h2>
      <p className="muted">
        New people need a one-time invite to create an account. It includes this server’s key, so their app can tell if someone else
        answers instead. To add them to a server, send them a server invite too.
      </p>
      <div className="row">
        <button disabled={busy} onClick={() => void run(() => window.silo.createAccountInvite(), setAccountInvite)}>
          Create sign-up code
        </button>
      </div>
      {accountInvite && (
        <p className="muted">
          Works once, expires {new Date(accountInvite.expiresAt).toLocaleString()}.
          <code className="block" data-testid="account-invite">{accountInvite.code}</code>
        </p>
      )}

      <h2>Connection</h2>
      <ConnectionSettings signedIn />

      {error && <div className="error">{error}</div>}

      <div className="row">
        <button disabled={busy} onClick={() => void run(() => window.silo.rotateRecoveryKey(), (v) => onRecoveryKey(v.recoveryKey))}>
          Replace recovery key
        </button>
        <button
          onClick={async () => {
            await window.silo.logout();
            onSignedOut();
          }}
        >
          Log out
        </button>
      </div>
    </div>
  );
}
