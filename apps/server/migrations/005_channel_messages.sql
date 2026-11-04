-- Encrypted channel messages. Each is encrypted once with the sender's sender key,
-- so the server keeps one copy per message rather than one per device.
CREATE TABLE channel_messages (
  seq            bigserial PRIMARY KEY,
  channel_id     uuid NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
  sender_user    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_device  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  body           bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX channel_messages_channel_idx ON channel_messages(channel_id, seq);
CREATE INDEX channel_messages_created_idx ON channel_messages(created_at);
