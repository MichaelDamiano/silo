-- People a user has blocked. Direct messages from them are dropped by the server.
CREATE TABLE user_blocks (
  blocker_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  blocked_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (blocker_id, blocked_id),
  CHECK (blocker_id <> blocked_id)
);
CREATE INDEX user_blocks_blocked_idx ON user_blocks(blocked_id);

-- Reports to a server's moderators. Messages are end-to-end encrypted, so the
-- excerpt is only what the reporter chose to share; moderators who can read the
-- channel check it against their own copy by sequence number.
CREATE TABLE reports (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  space_id          uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  channel_id        uuid REFERENCES channels(id) ON DELETE SET NULL,
  message_seq       bigint,
  reporter_id       uuid REFERENCES users(id) ON DELETE SET NULL,
  reported_user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  reason            text NOT NULL CHECK (reason IN ('spam', 'scam', 'harassment', 'malware', 'illegal', 'other')),
  note              text NOT NULL DEFAULT '',
  excerpt           text NOT NULL DEFAULT '',
  status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'dismissed')),
  resolved_by       uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz
);
CREATE INDEX reports_space_status_idx ON reports(space_id, status, created_at);
-- One open report per person per message, so nobody can stuff the queue.
CREATE UNIQUE INDEX reports_one_per_message ON reports(reporter_id, channel_id, message_seq) WHERE status = 'open' AND message_seq IS NOT NULL;
