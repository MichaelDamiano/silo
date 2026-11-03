import { useEffect, useState, type FormEvent } from 'react';
import type { AccountView, DeviceInfo, Result } from '../shared/ipc';

type Mode = 'signup' | 'login';

export function App() {
  const [device, setDevice] = useState<DeviceInfo>();
  const [account, setAccount] = useState<AccountView>();

  useEffect(() => {
    void window.silo.deviceInfo().then(setDevice);
  }, []);

  if (account) {
    return (
      <main>
        <div className="panel">
          <h1>Signed in as {account.username}</h1>
          <p className="muted">These devices can sign in to your account. Revoke any you don't recognise.</p>
          <ul className="devices">
            {account.devices.map((d) => (
              <li key={d.id}>
                {d.name} {d.current && <span className="muted">(this device)</span>}{' '}
                {d.revoked && <span className="muted">(revoked)</span>}
              </li>
            ))}
          </ul>
          <div className="row">
            <button
              onClick={async () => {
                await window.silo.logout();
                setAccount(undefined);
              }}
            >
              Log out
            </button>
          </div>
        </div>
      </main>
    );
  }

  return (
    <main>
      <div className="panel">
        <h1>Silo</h1>
        <p className="muted">Your account is tied to keys stored on this device. No email or phone number needed.</p>
        {device && !device.secureStorage && (
          <div className="warning">
            No system keychain was found, so this device's key can't be stored safely. Sign-in is disabled until one is installed.
          </div>
        )}
        <AuthForm onSignedIn={setAccount} disabled={!device?.secureStorage} />
        {device?.publicKey && (
          <p className="muted">
            Device key: <code>{device.publicKey}</code>
          </p>
        )}
      </div>
    </main>
  );
}

function AuthForm({ onSignedIn, disabled }: { onSignedIn: (a: AccountView) => void; disabled: boolean }) {
  const [mode, setMode] = useState<Mode>('signup');
  const [serverUrl, setServerUrl] = useState('http://localhost:8443');
  const [inviteCode, setInviteCode] = useState('');
  const [username, setUsername] = useState('');
  const [deviceName, setDeviceName] = useState('My computer');
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    const result: Result<AccountView> =
      mode === 'signup'
        ? await window.silo.signup({ serverUrl, inviteCode, username, deviceName })
        : await window.silo.login({ serverUrl });
    setBusy(false);
    if (result.ok) onSignedIn(result.value);
    else setError(result.error);
  }

  return (
    <form onSubmit={submit}>
      <div className="tabs">
        <button type="button" aria-pressed={mode === 'signup'} onClick={() => setMode('signup')}>
          Join with invite
        </button>
        <button type="button" aria-pressed={mode === 'login'} onClick={() => setMode('login')}>
          Log in
        </button>
      </div>
      <label htmlFor="server">Server address</label>
      <input id="server" value={serverUrl} onChange={(e) => setServerUrl(e.target.value)} required />
      {mode === 'signup' && (
        <>
          <label htmlFor="invite">Invite code</label>
          <input id="invite" value={inviteCode} onChange={(e) => setInviteCode(e.target.value)} required autoComplete="off" />
          <label htmlFor="username">Username</label>
          <input id="username" value={username} onChange={(e) => setUsername(e.target.value.toLowerCase())} required pattern="[a-z0-9_]{3,32}" />
          <label htmlFor="device">Name for this device</label>
          <input id="device" value={deviceName} onChange={(e) => setDeviceName(e.target.value)} required maxLength={64} />
        </>
      )}
      {error && <div className="error">{error}</div>}
      <div className="row">
        <button className="primary" type="submit" disabled={busy || disabled}>
          {mode === 'signup' ? 'Create account' : 'Log in'}
        </button>
      </div>
    </form>
  );
}
