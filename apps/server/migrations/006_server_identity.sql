-- The server's own Ed25519 identity key. It signs the list of addresses the server
-- can be reached at, so clients only ever switch to addresses the real server published.
CREATE TABLE server_identity (
  id          smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  public_key  text NOT NULL,
  secret_key  text NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
