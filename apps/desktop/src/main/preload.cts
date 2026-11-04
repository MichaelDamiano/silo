import { contextBridge, ipcRenderer } from 'electron';

// Channel names are duplicated from shared/ipc.ts because a sandboxed preload cannot import local files.
const invoke = (channel: string) => (input?: unknown) => ipcRenderer.invoke(channel, input);

contextBridge.exposeInMainWorld('silo', {
  deviceInfo: invoke('silo:device-info'),
  signup: invoke('silo:signup'),
  login: invoke('silo:login'),
  logout: invoke('silo:logout'),
  requestLink: invoke('silo:request-link'),
  checkLink: invoke('silo:check-link'),
  lookupLink: invoke('silo:lookup-link'),
  approveLink: invoke('silo:approve-link'),
  revokeDevice: invoke('silo:revoke-device'),
  recover: invoke('silo:recover'),
  rotateRecoveryKey: invoke('silo:rotate-recovery-key'),
  space: invoke('silo:space'),
  createAccountInvite: invoke('silo:create-account-invite'),
  dm: invoke('silo:dm'),
  channel: invoke('silo:channel'),
  connection: invoke('silo:connection'),
  safety: invoke('silo:safety'),
  onEvent: (listener: (event: unknown) => void) => {
    // Pass only the event data, never the IPC event object, to the page.
    const handler = (_e: unknown, event: unknown) => listener(event);
    ipcRenderer.on('silo:event', handler);
    return () => ipcRenderer.removeListener('silo:event', handler);
  },
});
