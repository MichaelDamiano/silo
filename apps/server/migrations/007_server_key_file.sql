-- The server identity's secret key can now live in a file outside the database
-- (SERVER_KEY_FILE). The database then keeps only the public key.
ALTER TABLE server_identity ALTER COLUMN secret_key DROP NOT NULL;
