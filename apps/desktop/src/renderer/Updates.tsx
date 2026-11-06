import { useEffect, useState } from 'react';
import type { UpdateAction, UpdateView } from '../shared/ipc';

function useUpdates() {
  const [view, setView] = useState<UpdateView>();
  const [error, setError] = useState<string>();
  useEffect(() => {
    void window.silo.update({ kind: 'get' }).then((r) => r.ok && setView(r.value));
    return window.silo.onEvent((e) => {
      if (e.type === 'update') setView(e.view);
    });
  }, []);
  const act = async (action: UpdateAction) => {
    setError(undefined);
    const r = await window.silo.update(action);
    if (r.ok) setView(r.value);
    else setError(r.error);
  };
  return { view, error, act };
}

/** A strip across the top when a newer signed version is ready or available. */
export function UpdateBanner() {
  const { view, error, act } = useUpdates();
  if (!view || (view.status !== 'ready' && view.status !== 'available')) return null;
  return (
    <div className="update-banner" data-testid="update-banner">
      {view.status === 'ready' ? (
        <>
          <span>Silo {view.version} is downloaded and checked.</span>
          <button className="primary" onClick={() => void act({ kind: 'install' })}>
            Restart to update
          </button>
        </>
      ) : (
        <>
          <span>Silo {view.version} is available.</span>
          {!view.canInstall && <button onClick={() => void act({ kind: 'openDownload' })}>Open download page</button>}
        </>
      )}
      {error && <span className="error-text">{error}</span>}
    </div>
  );
}

const STATUS: Record<UpdateView['status'], string> = {
  disabled: 'Automatic updates are off in this build.',
  idle: 'Not checked yet.',
  checking: 'Checking…',
  'up-to-date': 'You have the latest version.',
  available: 'A newer version is available.',
  downloading: 'Downloading the update…',
  ready: 'The update is downloaded and checked. Restart to install it.',
  error: 'The last check failed.',
};

/** The Updates part of settings. */
export function UpdateSettings() {
  const { view, error, act } = useUpdates();
  if (!view) return null;
  const busy = view.status === 'checking' || view.status === 'downloading';
  return (
    <div data-testid="update-settings">
      <p className="muted">
        Version {view.current}. {STATUS[view.status]}
        {view.status === 'downloading' && view.progress !== undefined && ` ${Math.round(view.progress * 100)}%`}
        {view.status === 'error' && view.error && ` ${view.error}`}
      </p>
      {view.status !== 'disabled' && (
        <>
          <p className="muted">
            Updates are only installed if they carry the Silo release signature, and the download matches it exactly. With “Send all traffic
            through Tor” on, update checks go through Tor too.
          </p>
          <label className="check">
            <input type="checkbox" checked={view.auto !== false} onChange={(e) => void act({ kind: 'setAuto', enabled: e.target.checked })} /> Check
            for updates automatically
          </label>
          <div className="row">
            <button disabled={busy} onClick={() => void act({ kind: 'check' })}>
              Check now
            </button>
            {view.status === 'ready' && (
              <button className="primary" onClick={() => void act({ kind: 'install' })}>
                Restart to update
              </button>
            )}
          </div>
        </>
      )}
      {error && <div className="error">{error}</div>}
    </div>
  );
}
