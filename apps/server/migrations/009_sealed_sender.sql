-- Sealed sender: a sealed envelope reaches the server without saying who sent it,
-- so its sender columns are empty. Only the recipient learns the sender, from the
-- certificate inside the encryption.
ALTER TABLE envelopes ALTER COLUMN sender_user DROP NOT NULL;
ALTER TABLE envelopes ALTER COLUMN sender_device DROP NOT NULL;
ALTER TABLE envelopes ADD CONSTRAINT envelopes_sender_check
  CHECK ((message_type = 6) = (sender_user IS NULL AND sender_device IS NULL));

-- Each person's access key. Anyone who shows it may drop sealed messages in their
-- mailbox; people get it inside an encrypted message from them. It is kept as is so
-- all of the account's devices can read it; it gates nothing the server couldn't do itself.
ALTER TABLE users ADD COLUMN access_key text CHECK (access_key ~ '^[A-Za-z0-9_-]{22}$');
