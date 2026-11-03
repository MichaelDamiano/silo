-- Signal protocol keys, one set per device. The server only ever holds public keys.
ALTER TABLE devices
  -- Signal addresses devices by a small number (1 to 127) within each account.
  ADD COLUMN signal_device_id smallint CHECK (signal_device_id BETWEEN 1 AND 127),
  ADD COLUMN signal_registration_id integer,
  ADD COLUMN signal_identity_key text,
  -- The device's Ed25519 key signs its Signal identity key, tying the two together.
  ADD COLUMN signal_identity_signature text,
  ADD COLUMN signed_prekey_id integer,
  ADD COLUMN signed_prekey text,
  ADD COLUMN signed_prekey_signature text,
  ADD COLUMN kyber_prekey_id integer,
  ADD COLUMN kyber_prekey text,
  ADD COLUMN kyber_prekey_signature text;
CREATE UNIQUE INDEX devices_signal_device_id ON devices(user_id, signal_device_id) WHERE signal_device_id IS NOT NULL;

-- One-time pre-keys. Each is handed out once and then deleted.
CREATE TABLE one_time_prekeys (
  device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  key_id      integer NOT NULL,
  public_key  text NOT NULL,
  PRIMARY KEY (device_id, key_id)
);

-- Encrypted envelopes waiting for a device to fetch them. Deleted once acknowledged.
CREATE TABLE envelopes (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_device  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  sender_user       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_device     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  message_type      smallint NOT NULL,
  body              bytea NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX envelopes_recipient_idx ON envelopes(recipient_device, created_at);
