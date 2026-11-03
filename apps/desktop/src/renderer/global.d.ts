import type { SiloBridge } from '../shared/ipc';

declare global {
  interface Window {
    silo: SiloBridge;
  }
}
