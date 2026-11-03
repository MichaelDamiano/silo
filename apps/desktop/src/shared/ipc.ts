/** The only API the renderer can call. It never exposes the device's secret key or session token. */
export interface SiloBridge {
  deviceInfo(): Promise<DeviceInfo>;
  signup(input: SignupInput): Promise<Result<AccountView>>;
  login(input: { serverUrl: string }): Promise<Result<AccountView>>;
  logout(): Promise<void>;
}

export interface DeviceInfo {
  publicKey: string;
  /** False when the OS keychain is missing and the key could not be stored safely. */
  secureStorage: boolean;
}

export interface SignupInput {
  serverUrl: string;
  inviteCode: string;
  username: string;
  deviceName: string;
}

export interface AccountView {
  username: string;
  devices: { id: string; name: string; current: boolean; revoked: boolean; createdAt: string }[];
}

export type Result<T> = { ok: true; value: T } | { ok: false; error: string };

export const IPC = {
  deviceInfo: 'silo:device-info',
  signup: 'silo:signup',
  login: 'silo:login',
  logout: 'silo:logout',
} as const;
