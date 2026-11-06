import { app, BrowserWindow, ipcMain, Menu, protocol, safeStorage, session, shell, type IpcMainInvokeEvent } from 'electron';
import { spawn } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { allowedRequest, APP_INDEX, APP_SCHEME, isAppPage, RENDERER_CSP, resolveAppFile } from './app-protocol.js';
import { IPC, type RecoverInput, type Result, type SignupInput, type UpdateAction } from '../shared/ipc.js';
import { fetch as undiciFetch } from 'undici';
import { DEFAULT_TOR, socksAgent, type TorSettings } from './transport.js';
import { UPDATE_FEED, UPDATE_KEYS } from './update-config.js';
import { Updater } from './updater.js';
import { SiloClient } from './api.js';
import { loadOrCreateDeviceKey, type SecretBox } from './keystore.js';
import { Vault } from './vault.js';
import type { AppEvent } from '../shared/ipc.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const rendererDir = path.join(here, '../renderer');
const dev = !app.isPackaged;

// A release build refuses debugger switches, which would let anything that can start
// Silo drive the signed-in app. The fuses already block Node's own --inspect flags.
const DEBUG_SWITCHES = ['remote-debugging-port', 'remote-debugging-pipe', 'remote-allow-origins', 'inspect', 'inspect-brk', 'js-flags'];
if (!dev && DEBUG_SWITCHES.some((s) => app.commandLine.hasSwitch(s))) {
  console.error('Silo: debugging switches are disabled in release builds.');
  app.exit(1);
}

// Harden before any window exists.
app.enableSandbox();
protocol.registerSchemesAsPrivileged([{ scheme: APP_SCHEME, privileges: { standard: true, secure: true } }]);

// One copy at a time, so two processes never write the same vault and key files.
if (!app.requestSingleInstanceLock()) app.exit(0);
app.on('second-instance', () => {
  if (mainWindow?.isMinimized()) mainWindow.restore();
  mainWindow?.focus();
});

// Applies to every web page Electron creates, including any we didn't make ourselves.
app.on('web-contents-created', (_e, contents) => {
  contents.on('will-navigate', (e) => e.preventDefault());
  contents.on('will-redirect', (e) => e.preventDefault());
  contents.on('will-attach-webview', (e) => e.preventDefault());
  contents.setWindowOpenHandler(() => ({ action: 'deny' }));
});

let client: SiloClient | undefined;
let mainWindow: BrowserWindow | undefined;

function emit(event: AppEvent) {
  mainWindow?.webContents.send(IPC.event, event);
}

/** Only our own bundled page may call into the main process. */
function trusted(event: IpcMainInvokeEvent): boolean {
  return isAppPage(event.senderFrame?.url) && event.senderFrame === mainWindow?.webContents.mainFrame;
}

async function wrap<T>(fn: () => Promise<T>): Promise<Result<T>> {
  try {
    return { ok: true, value: await fn() };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

function handle(channel: string, fn: (...args: any[]) => Promise<unknown>) {
  ipcMain.handle(channel, (event, ...args) => {
    if (!trusted(event)) throw new Error('untrusted sender');
    return fn(...args);
  });
}

async function createWindow() {
  const win = (mainWindow = new BrowserWindow({
    width: 1100,
    height: 720,
    title: 'Silo',
    webPreferences: {
      preload: path.join(here, 'preload.cjs'),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
      devTools: dev,
      webviewTag: false,
      navigateOnDragDrop: false,
    },
  }));
  win.on('closed', () => {
    if (mainWindow === win) mainWindow = undefined;
  });
  await win.loadURL(APP_INDEX);
}

app.whenReady().then(async () => {
  // Deny camera, microphone, notifications, geolocation and every other permission by default.
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.setDevicePermissionHandler(() => false);
  // The page talks to the network only through the main process, so it may load nothing but its own files.
  session.defaultSession.webRequest.onBeforeRequest((details, cb) => cb({ cancel: !allowedRequest(details.url, dev) }));
  protocol.handle(APP_SCHEME, async (request) => {
    const hit = resolveAppFile(rendererDir, request.url);
    if (!hit || request.method !== 'GET') return new Response('not found', { status: 404 });
    try {
      return new Response(await readFile(hit.file), {
        headers: {
          'content-type': hit.type,
          'content-security-policy': RENDERER_CSP,
          'x-content-type-options': 'nosniff',
          'cross-origin-opener-policy': 'same-origin',
        },
      });
    } catch {
      return new Response('not found', { status: 404 });
    }
  });
  // No Reload or Toggle DevTools in release builds; keep the standard edit and window menus.
  if (!dev) {
    Menu.setApplicationMenu(
      Menu.buildFromTemplate([
        ...(process.platform === 'darwin' ? [{ role: 'appMenu' as const }] : []),
        { role: 'editMenu' },
        { role: 'windowMenu' },
      ]),
    );
  }

  const keyFile = path.join(app.getPath('userData'), 'device-key.bin');
  // Electron's Linux fallback backend "basic_text" is not a real keychain, so treat it as unavailable.
  const weakBackend = process.platform === 'linux' && safeStorage.getSelectedStorageBackend() === 'basic_text';
  const box: SecretBox = {
    isAvailable: async () => !weakBackend && (await safeStorage.isAsyncEncryptionAvailable()),
    encrypt: (plain) => safeStorage.encryptStringAsync(plain.toString('base64')),
    decrypt: async (sealed) => {
      const { result, shouldReEncrypt } = await safeStorage.decryptStringAsync(sealed);
      return { plain: Buffer.from(result, 'base64'), shouldReEncrypt };
    },
  };
  let secureStorage = true;
  try {
    const key = await loadOrCreateDeviceKey(keyFile, box);
    const vault = await Vault.open(app.getPath('userData'), box);
    client = new SiloClient(key, vault, emit);
  } catch {
    secureStorage = false;
  }

  const need = () => {
    if (!client) throw new Error('This device has no protected key. Install a system keychain (for example GNOME Keyring) and restart.');
    return client;
  };

  handle(IPC.deviceInfo, async () => ({ publicKey: client?.publicKey ?? '', fingerprint: client?.fingerprint ?? '', secureStorage }));
  handle(IPC.signup, (input: SignupInput) => wrap(() => need().signup(input)));
  handle(IPC.login, (input: { serverUrl: string }) => wrap(() => need().login(input.serverUrl)));
  handle(IPC.logout, async () => {
    await client?.logout().catch(() => undefined);
  });
  handle(IPC.requestLink, (input: { serverUrl: string; username: string; deviceName: string }) =>
    wrap(() => need().requestLink(input)),
  );
  handle(IPC.checkLink, () => wrap(() => need().checkLink()));
  handle(IPC.lookupLink, (input: { pairingCode: string }) => wrap(() => need().lookupLink(input.pairingCode)));
  handle(IPC.approveLink, () => wrap(() => need().approveLink()));
  handle(IPC.revokeDevice, (input: { deviceId: string }) => wrap(() => need().revokeDevice(input.deviceId)));
  handle(IPC.recover, (input: RecoverInput) => wrap(() => need().recover(input)));
  handle(IPC.rotateRecoveryKey, () => wrap(() => need().rotateRecoveryKey()));
  handle(IPC.createAccountInvite, () => wrap(() => need().createAccountInvite()));
  handle(IPC.dm, (action: unknown) => wrap(() => need().dm(action)));
  handle(IPC.channel, (action: unknown) => wrap(() => need().channel(action)));
  handle(IPC.connection, (action: unknown) => wrap(() => need().connection(action)));
  handle(IPC.space, (action: unknown) => wrap(() => need().space(action)));
  handle(IPC.safety, (action: unknown) => wrap(() => need().safety(action)));

  setupUpdates(() => client?.torSettings() ?? Promise.resolve(DEFAULT_TOR));

  await createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) void createWindow();
  });
});

const UPDATE_EVERY = 6 * 60 * 60_000;

/** Signed automatic updates. Off in development builds, which have no reason to replace themselves. */
function setupUpdates(tor: () => Promise<TorSettings>) {
  const prefsFile = path.join(app.getPath('userData'), 'updates.json');
  let auto = true;
  const updater = new Updater({
    currentVersion: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    feed: UPDATE_FEED,
    keys: dev ? [] : UPDATE_KEYS,
    dir: path.join(app.getPath('userData'), 'updates'),
    // When Silo is set to send everything through Tor, update checks go through Tor too, on their own circuit.
    fetch: async (url, init) => {
      const t = await tor();
      const dispatcher = t.always ? socksAgent(t, true) : undefined;
      try {
        const res = await undiciFetch(url, { ...init, redirect: 'follow', ...(dispatcher ? { dispatcher } : {}) });
        return res as unknown as Response;
      } finally {
        // close() lets the response body finish streaming, then frees the connection.
        if (dispatcher) void dispatcher.close();
      }
    },
    launch: (installer) => {
      // electron-builder's installer: /S installs silently, --updated keeps settings, --force-run starts Silo again.
      spawn(installer, ['--updated', '/S', '--force-run'], { detached: true, stdio: 'ignore' }).unref();
      app.quit();
    },
    onChange: (view) => emit({ type: 'update', view: { ...view, auto } }),
  });
  const view = () => ({ ...updater.state, auto });

  void readFile(prefsFile, 'utf8')
    .then((t) => {
      auto = (JSON.parse(t) as { auto?: unknown }).auto !== false;
    })
    .catch(() => undefined)
    .finally(() => {
      const tick = () => auto && void updater.check();
      setTimeout(tick, 15_000).unref();
      setInterval(tick, UPDATE_EVERY).unref();
    });

  handle(IPC.update, (action: UpdateAction) =>
    wrap(async () => {
      switch (action?.kind) {
        case 'check':
          await updater.check();
          break;
        case 'install':
          await updater.install();
          break;
        case 'openDownload':
          // A fixed address, never one from the network.
          await shell.openExternal(`${UPDATE_FEED}/latest`);
          break;
        case 'setAuto':
          auto = action.enabled === true;
          await writeFile(prefsFile, JSON.stringify({ auto }));
          break;
      }
      return view();
    }),
  );
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
