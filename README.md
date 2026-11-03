# Silo

An invite-only, end-to-end encrypted messaging app with servers, channels and direct messages, built to keep working when the main server is blocked or down.

> Status: early prototype. Accounts, devices, recovery keys, servers, channels, roles and moderation work. End-to-end encrypted messaging is next.

## How accounts work

- There is no email or phone number. You join with an invite code and pick a username.
- Each device creates its own Ed25519 key on first run and keeps the secret key encrypted by the OS keychain (Keychain on macOS, DPAPI on Windows, libsecret on Linux). If no keychain is available, the app refuses to store the key rather than saving it in plain text.
- To sign in, the device signs a one-time challenge from the server. There is no password to phish or reuse.
- You can see every device on your account and revoke one, which ends its sessions immediately.
- To add another device, it shows a pairing code and its key fingerprint. You enter the code on a device that's already signed in, check that the fingerprints match, and approve. The approving device signs the new key, and the server keeps that signature.
- At sign-up you get a recovery key to write down. It is a separate key that is never stored on the device. If you lose every device, it signs you in on a new one, revokes all the old ones and is replaced with a fresh key.
- The server stores session tokens and invite codes only as SHA-256 hashes, and does not log IP addresses.

## Servers

- Anyone signed in can create a server. It starts with a `#general` channel.
- Owners and admins add or remove channels, create server invites, and kick, ban or unban people. Admins can only act on members; only the owner can make or remove admins.
- Server invites are separate from sign-up codes, are stored hashed, and have a use limit and expiry. Banned people can't rejoin with any invite.
- People outside a server get the same "not found" answer as for a server that doesn't exist.

## Layout

| Path | What it is |
| --- | --- |
| `packages/protocol` | Shared request schemas and signing helpers used by both sides |
| `apps/server` | Node + Fastify API with Postgres |
| `apps/desktop` | Electron + React desktop client |

## Running it locally

You need Node 22, plus Docker or a local Postgres 16.

```sh
npm install
```

**Option A: Docker runs Postgres and the server**

```sh
docker compose up --build
# Create the first invite (nobody exists yet to make one in the app)
docker compose exec server node apps/server/dist/cli/create-invite.js --uses 5 --hours 72
```

**Option B: your own Postgres**

```sh
export DATABASE_URL=postgres://silo:silo@localhost:5432/silo
npm run build -w @silo/protocol
npm run dev -w @silo/server
npm run invite:create -w @silo/server -- --uses 5 --hours 72
```

Then start the desktop app and join with that code at `http://localhost:8443`:

```sh
npm run dev -w @silo/desktop
```

On Linux the desktop app needs a running keychain such as GNOME Keyring or KWallet.

## Tests

```sh
# Server tests need a Postgres database they are allowed to wipe
export TEST_DATABASE_URL=postgres://silo:silo@localhost:5432/silo_test
npm run build -w @silo/protocol
npm run typecheck
npm test
```

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
