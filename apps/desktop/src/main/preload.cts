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
});
