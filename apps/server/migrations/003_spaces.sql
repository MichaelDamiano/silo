-- Spaces are what the app calls servers: a group with channels and members.
CREATE TABLE spaces (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE space_members (
  space_id    uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
  joined_at   timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space_id, user_id)
);
CREATE INDEX space_members_user_id_idx ON space_members(user_id);
-- Exactly one owner per space.
CREATE UNIQUE INDEX space_members_one_owner ON space_members(space_id) WHERE role = 'owner';

CREATE TABLE space_bans (
  space_id    uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  banned_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (space_id, user_id)
);

CREATE TABLE channels (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  space_id    uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  name        text NOT NULL,
  position    integer NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (space_id, name)
);

-- Invite codes are stored only as SHA-256 hashes.
CREATE TABLE space_invites (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  space_id    uuid NOT NULL REFERENCES spaces(id) ON DELETE CASCADE,
  code_hash   bytea NOT NULL UNIQUE,
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  max_uses    integer NOT NULL CHECK (max_uses > 0),
  uses        integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
  expires_at  timestamptz NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
