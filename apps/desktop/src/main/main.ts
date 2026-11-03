import { app, BrowserWindow, ipcMain, safeStorage, session, type IpcMainInvokeEvent } from 'electron';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { IPC, type RecoverInput, type Result, type SignupInput } from '../shared/ipc.js';
import { SiloClient } from './api.js';
import { loadOrCreateDeviceKey, type SecretBox } from './keystore.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const rendererIndex = path.join(here, '../renderer/index.html');
const rendererUrl = pathToFileURL(rendererIndex).href;

// Harden before any window exists.
app.enableSandbox();

let client: SiloClient | undefined;

/** Only our own bundled page may call into the main process. */
function trusted(event: IpcMainInvokeEvent): boolean {
  return event.senderFrame?.url === rendererUrl;
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
  const win = new BrowserWindow({
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
    },
  });
  // The window only ever shows our bundled page: no navigation, no pop-ups.
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  await win.loadFile(rendererIndex);
}

app.whenReady().then(async () => {
  // Deny camera, microphone, notifications, geolocation and every other permission by default.
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);

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
    client = new SiloClient(await loadOrCreateDeviceKey(keyFile, box));
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
  handle(IPC.space, (action: unknown) => wrap(() => need().space(action)));

  await createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) void createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
