-- The recovery key is a separate key the user writes down at sign-up.
ALTER TABLE users ADD COLUMN recovery_public_key text UNIQUE;

-- Every device after the first is vouched for by an existing device's signature.
ALTER TABLE devices
  ADD COLUMN approved_by uuid REFERENCES devices(id) ON DELETE SET NULL,
  ADD COLUMN approval_signature text;

-- A new device waiting to be approved from an existing one.
CREATE TABLE device_links (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  pairing_code_hash  bytea NOT NULL UNIQUE,
  device_name        text NOT NULL,
  public_key         text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  approved_at        timestamptz
);
CREATE INDEX device_links_user_id_idx ON device_links(user_id);
