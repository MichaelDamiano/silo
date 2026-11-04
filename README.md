# Silo

An invite-only, end-to-end encrypted messaging app with servers, channels and direct messages, built to keep working when the main server is blocked or down.

> Status: early prototype. Accounts, devices, recovery keys, servers, roles, moderation, and end-to-end encrypted direct messages and channel messages work. Fallback addresses, relays, Tor onion access and local-network delivery work. Hardening for an outside review is under way; see [SECURITY.md](SECURITY.md).

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

## Direct messages

- DMs use the Signal protocol through Signal's own audited library, [libsignal](https://github.com/signalapp/libsignal), with post-quantum (PQXDH) session setup and the Double Ratchet for forward secrecy.
- Each device publishes its own Signal keys. Its login key signs its Signal identity key, and senders check that signature before starting a session.
- A message is encrypted separately for every device of the recipient and for the sender's other devices. If the sender's device list is out of date, the server rejects the send and says which devices were added or removed.
- The server stores only ciphertext, deletes it once the device confirms receipt, and drops anything unclaimed after 30 days. A WebSocket nudges online devices to fetch new messages; no message content goes over it.
- You can DM people you share a server with. If someone's encryption key changes unexpectedly, their messages are blocked rather than trusted.
- On the device, Signal state and message history are stored encrypted with AES-256-GCM under a key sealed by the OS keychain.
- A newly linked device sees messages from the moment it joins, not older history.

## Channel messages

- Channels use Signal's sender keys, also through libsignal. Each device has its own key per channel and hands it to every member device over their pairwise Signal sessions, so the server can't swap or read it.
- Each message is then encrypted once and signed with the sender's key. The server stores one copy and serves it to members' devices, which check the signature and that the message really belongs to that channel.
- When someone leaves or is kicked or banned, or a device is revoked, each sender replaces its key before its next message, so the removed devices can't read anything new.
- A device only gets messages sent after both it and its account joined. If a message arrives before its key, it waits for the key for up to 7 days.
- The server deletes channel ciphertext after 30 days. Decrypted history stays on each device in the encrypted vault.

## Staying connected

- A server can be reached at several addresses: its main one, mirrors or relays, and a Tor onion address. It publishes the list signed with its own identity key, which each device pins the first time it connects.
- If the address in use stops working, the app moves to the next one by itself and stays there. It only ever uses addresses the server signed or that you added, and it refuses any address that answers with a different identity key than before.
- You can add an address by hand, for example an onion address a friend sends you when the main one is blocked. It's only added if the same server answers there.
- Onion addresses go through Tor's SOCKS proxy (the Tor service on port 9050, or Tor Browser on 9150). You can also send all traffic through Tor so the server never sees your IP address.
- A request that might already have reached the server is only retried on another address if it's safe to repeat, so a flaky connection doesn't send things twice.

### When the server can't be reached at all

- Turn on **local network** in Connection settings and the app looks for other Silo devices on the same Wi-Fi or LAN. It's off by default.
- The announcement only says that a Silo device is listening on a port, not whose it is. Devices then link up only if each knows the other's login key from a server they share, which they remember while online.
- Each link uses a fresh X25519 key exchange, signed by both devices' login keys, and AES-256-GCM in both directions. What travels over it is the same end-to-end encrypted Signal messages the server would carry.
- If the server is unreachable, DMs and channel messages go straight to the people linked on your network, marked as sent locally. When the server is back they're sent through it as well, so everyone else gets them. Nobody sees them twice.
- For now this only works while the app is already running and signed in when the server goes down. It also needs an earlier conversation with that person (an existing Signal session).

### Running a Tor onion service

```sh
docker compose --profile tor up --build
```

Tor creates the onion address on first start and prints it. The server picks it up and publishes it to clients automatically. The onion keys live in the `tor-keys` volume, so back that up to keep the same address.

### Running a relay

`tools/relay/relay.mjs` forwards raw TCP to the server without decrypting anything, so it never sees tokens or messages. It has no dependencies and logs no addresses.

```sh
LISTEN=0.0.0.0:443 UPSTREAM=silo.example.com:443 node tools/relay/relay.mjs
```

Then add the relay to the server's published list, for example `PUBLIC_URLS=https://relay.example.net`. The server's TLS certificate must also cover the relay's hostname. Plain `http://` addresses are only allowed for localhost and onion services.

## Limits against abuse

- Signed-in requests are rate limited per account, not per session, so signing in again doesn't reset anything. People sharing an IP address (a household, an office, Tor) don't block each other.
- Each device keeps at most 5 sessions, and older ones are signed out. Each person can have 10 unused sign-up codes and be in 200 servers.
- A device with 5,000 undelivered messages stops accepting more until it catches up, so nobody can fill the server's disk by flooding one person.

## Running it in production

- Set `SERVER_KEY_FILE` so the server's identity secret lives in a file only the server can read, not in the database or its backups. Docker Compose does this with the `server-keys` volume. Back that volume up: if the key is lost, every client sees a new server it doesn't trust.
- The Compose services run read-only, as non-root, with all Linux capabilities dropped and `no-new-privileges`.
- Put the server behind TLS (a reverse proxy or a relay in front of one) and set `PUBLIC_URLS` to the addresses you publish.

## Desktop releases

- `npm run dist -w @silo/desktop` builds an installer for the current platform into `apps/desktop/release`.
- Release builds turn off the Electron features an attacker with local access could use to run their own code as Silo, refuse debugger switches, and serve the app only from `app://silo/`.
- Builds are reproducible: anyone can rebuild a release and check it with `npm run verify-release -w @silo/desktop -- <download>`. See [docs/reproducible-builds.md](docs/reproducible-builds.md).
- Pushing a `v*` tag builds Linux, macOS and Windows versions and attaches them, with checksums, to a draft GitHub release.

## Layout

| Path | What it is |
| --- | --- |
| `packages/protocol` | Shared request schemas and signing helpers used by both sides |
| `packages/signal` | The Signal protocol engine for one device, built on libsignal |
| `apps/server` | Node + Fastify API with Postgres |
| `apps/desktop` | Electron + React desktop client |
| `tools/relay` | A tiny TCP relay for when the main address is blocked |
| `tools/tor` | Tor onion service image used by Docker Compose |

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
npm run build -w @silo/protocol && npm run build -w @silo/signal
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
npm run build -w @silo/protocol && npm run build -w @silo/signal
npm run typecheck
npm test
```

## License

GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
