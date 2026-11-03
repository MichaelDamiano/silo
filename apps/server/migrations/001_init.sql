-- Accounts are a username plus a set of device keys. No email or phone.
CREATE TABLE users (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username    text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- One row per device. The private key never leaves the device.
CREATE TABLE devices (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name        text NOT NULL,
  public_key  text NOT NULL UNIQUE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  revoked_at  timestamptz
);
CREATE INDEX devices_user_id_idx ON devices(user_id);

-- Invite codes are stored only as SHA-256 hashes.
CREATE TABLE invites (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code_hash   bytea NOT NULL UNIQUE,
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  max_uses    integer NOT NULL CHECK (max_uses > 0),
  uses        integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Single-use nonces that a device signs to prove it holds its private key.
CREATE TABLE challenges (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  public_key  text NOT NULL,
  nonce       text NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);
CREATE INDEX challenges_expires_at_idx ON challenges(expires_at);

-- Session tokens are stored only as SHA-256 hashes.
CREATE TABLE sessions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash  bytea NOT NULL UNIQUE,
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  revoked_at  timestamptz
);
CREATE INDEX sessions_device_id_idx ON sessions(device_id);
