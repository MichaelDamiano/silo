import { contextBridge, ipcRenderer } from 'electron';

// Channel names are duplicated from shared/ipc.ts because a sandboxed preload cannot import local files.
const bridge = {
  deviceInfo: () => ipcRenderer.invoke('silo:device-info'),
  signup: (input: unknown) => ipcRenderer.invoke('silo:signup', input),
  login: (input: unknown) => ipcRenderer.invoke('silo:login', input),
  logout: () => ipcRenderer.invoke('silo:logout'),
};

contextBridge.exposeInMainWorld('silo', bridge);
