import { useEffect, useState } from 'react';
import type { ConnectionView } from '../shared/ipc';

/** Shows which address is in use and lets people add fallback addresses and set up Tor. */
export function ConnectionSettings({ signedIn }: { signedIn: boolean }) {
  const [view, setView] = useState<ConnectionView>();
  const [host, setHost] = useState('127.0.0.1');
  const [port, setPort] = useState('9050');
  const [always, setAlways] = useState(false);
  const [address, setAddress] = useState('');
  const [error, setError] = useState<string>();
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  const apply = (v: ConnectionView) => {
    setView(v);
    setHost(v.tor.proxyHost);
    setPort(String(v.tor.proxyPort));
    setAlways(v.tor.always);
  };

  useEffect(() => {
    void window.silo.connection({ kind: 'get' }).then((r) => r.ok && apply(r.value));
    const off = window.silo.onEvent((e) => {
      if (e.type === 'connection') void window.silo.connection({ kind: 'get' }).then((r) => r.ok && setView(r.value));
    });
    return () => {
      off();
    };
  }, []);

  async function act(fn: () => ReturnType<typeof window.silo.connection>, after?: () => void) {
    setBusy(true);
    setError(undefined);
    setSaved(false);
    const r = await fn();
    setBusy(false);
    if (r.ok) {
      apply(r.value);
      after?.();
    } else setError(r.error);
  }

  return (
    <div className="connection" data-testid="connection">
      {signedIn && view?.current && (
        <p data-testid="current-address">
          Connected to <code>{view.current.endpoint}</code>
          {view.current.viaTor ? ' through Tor' : ''}. Server identity <code>{view.serverFingerprint}</code>.
        </p>
      )}
      {signedIn && view && view.addresses.length > 0 && (
        <>
          <p className="muted">
            If an address stops working, Silo moves to the next one by itself. The server signs its list, so only addresses it published or you
            added are ever used.
          </p>
          <ul className="devices" data-testid="addresses">
            {view.addresses.map((a) => (
              <li key={a.endpoint}>
                <div>
                  <code>{a.endpoint}</code> <span className="muted">{a.onion ? '(Tor) ' : ''}{a.published ? '' : '(added by you)'}</span>
                </div>
                {!a.published && (
                  <button disabled={busy} onClick={() => void act(() => window.silo.connection({ kind: 'removeAddress', address: a.endpoint }))}>
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void act(() => window.silo.connection({ kind: 'addAddress', address }), () => setAddress(''));
            }}
          >
            <label htmlFor="add-address">Add another address for this server</label>
            <input id="add-address" placeholder="https://… or http://….onion" value={address} onChange={(e) => setAddress(e.target.value)} required />
            <div className="row">
              <button type="submit" disabled={busy}>Check and add</button>
            </div>
          </form>
        </>
      )}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void act(
            () => window.silo.connection({ kind: 'setTor', proxyHost: host.trim(), proxyPort: Number(port), always }),
            () => setSaved(true),
          );
        }}
      >
        <p className="muted">
          Onion addresses go through Tor. Run the Tor service (port 9050) or keep Tor Browser open (port 9150).
        </p>
        <div className="row">
          <div>
            <label htmlFor="tor-host">Tor proxy host</label>
            <input id="tor-host" value={host} onChange={(e) => setHost(e.target.value)} required />
          </div>
          <div>
            <label htmlFor="tor-port">Port</label>
            <input id="tor-port" type="number" min={1} max={65535} value={port} onChange={(e) => setPort(e.target.value)} required />
          </div>
        </div>
        <label className="check">
          <input type="checkbox" checked={always} onChange={(e) => setAlways(e.target.checked)} /> Send all traffic through Tor, so the server
          never sees this computer’s IP address
        </label>
        <div className="row">
          <button type="submit" disabled={busy}>Save Tor settings</button>
          {saved && <span className="muted">Saved.</span>}
        </div>
      </form>
      {error && <div className="error">{error}</div>}
    </div>
  );
}
