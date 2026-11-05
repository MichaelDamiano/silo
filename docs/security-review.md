# Silo: guide for outside security reviewers

This is the starting point for anyone reviewing Silo's security. It explains what
Silo protects, how, and which parts we most want checked. The threat model this
builds on is at https://claude.ai/artifact/JHDMGgB9zdw8f48bJEwZLN. Where the two
disagree, this file and the code win: it describes what was actually built.

Silo has had no outside review yet. Please treat every claim here as something
to test, not something to trust.

## 1. What Silo is

Silo is an invite-only, self-hostable group chat app, like Discord: servers
(called "spaces" in the code), text channels, and direct messages. Every message
is end-to-end encrypted. Accounts need no email or phone number; each device has
its own keys. The desktop app can reach a server directly, through relays, or
over Tor, and can pass messages to nearby devices on the local network when the
server is unreachable.

Status: a working prototype, desktop only, text only.

## 2. Scope

Review the commit you were given, or the tip of `main`.

| In scope | Path |
| --- | --- |
| API server (Node, Fastify, Postgres) | `apps/server` |
| Desktop app (Electron main process, preload, React renderer) | `apps/desktop` |
| Shared request schemas and signing payloads | `packages/protocol` |
| Signal protocol wrapper around libsignal | `packages/signal` |
| Relay and Tor images, Docker Compose setup | `tools/`, `docker-compose.yml` |
| CI, release and dependency setup | `.github/` |

Out of scope: libsignal itself (report to security@signal.org), Electron and
Chromium, Tor, Postgres, and the operating system keychain. How Silo *uses* each
of those is in scope.

Test only against a server you run yourself (section 9). Report findings as
described in [SECURITY.md](../SECURITY.md).

## 3. Architecture and trust boundaries

```
 ┌──────────── desktop app (one per device) ────────────┐
 │ renderer (React)  ──IPC, schema-checked──▶  main process │
 │ sandboxed, no Node,        │   login key, Signal state,  │
 │ app://silo only            │   vault, all networking     │
 └────────────────────────────┼────────────────────────────┘
                              │ HTTPS / WSS, directly, via relay, or via Tor SOCKS
                              ▼
                     ┌──────────────────┐        ┌──────────┐
                     │  Silo server     │──SQL──▶│ Postgres │
                     │ (sees ciphertext │        └──────────┘
                     │  and metadata)   │
                     └──────────────────┘
 desktop ◀── LAN: multicast beacon + signed X25519 link, AES-256-GCM ──▶ desktop
```

Trust boundaries, from least to most trusted:

1. **The network, relays and Tor.** Untrusted. Clients pin the server's identity
   key and check its signed address list before using any address.
2. **The server.** Trusted to deliver messages and to enforce membership, roles,
   bans and limits. *Not* trusted with message contents. It is also not trusted
   to hand out honest keys: safety numbers exist to catch a server that lies
   about devices or keys.
3. **The renderer.** Treated as untrusted by the main process. It never sees
   secret keys, session tokens or the vault key. Every IPC call is checked
   against a zod schema in `apps/desktop/src/main`.
4. **The main process and the OS keychain.** Trusted. They hold this device's
   secrets.

## 4. What we protect

| Asset | Where it lives |
| --- | --- |
| Message contents | Only on devices: in memory, and in the vault (AES-256-GCM files whose key the OS keychain seals) |
| Device login key (Ed25519) | `device-key.bin`, sealed by the OS keychain (`apps/desktop/src/main/keystore.ts`) |
| Signal identity, sessions and sender keys | The vault, file `signal` |
| Recovery key | Shown once at sign-up. The server keeps only its public half |
| Server identity key (Ed25519) | `SERVER_KEY_FILE` (mode 0600), never in the database once that is set |
| Session tokens and invite codes | The server stores only SHA-256 hashes |
| Metadata (who talks to whom, when, sizes, memberships, blocks, reports) | The server. See section 7 |

## 5. Threats and how each is handled

These are the threats the project owner named, with where to look.

| Threat | What Silo does | Code |
| --- | --- | --- |
| Account takeover | No passwords. Signing in is a challenge signed by a device key. New devices need approval from an existing device, which compares a fingerprint. The recovery key revokes **all** devices and sessions. Each device keeps at most 5 sessions | `apps/server/src/routes/accounts.ts`, `devices.ts`, `auth.ts` |
| Server or network impersonation | Sign-up invites carry the server's identity key, which is checked before first contact. Otherwise the key is pinned on first contact. It signs the address list (`serverInfo` payload, with a client nonce) | `apps/server/src/routes/server-info.ts`, `apps/desktop/src/main/servers.ts` |
| Reading messages (server, network, other members) | libsignal PQXDH plus Double Ratchet for DMs, sender keys for channels. A key is rotated when a member device leaves | `packages/signal/src/index.ts`, `apps/desktop/src/main/messenger.ts` |
| A server adding a fake device or key | The server never replaces a device's identity key (`PUT /v1/keys` refuses). Safety numbers cover every device on both sides, and the app warns when a verified number changes. A changed key blocks messages until the user accepts it | `packages/signal/src/safety.ts`, `apps/desktop/src/main/safety.ts` |
| Malware and code injection into the app | Sandboxed renderer, context isolation, strict CSP, the `app://` scheme with containment of the requested path, no navigation, pop-ups or webviews, and no network access from the renderer. Release builds set Electron fuses (no RunAsNode, NODE_OPTIONS or inspect, asar integrity, only load from asar) and refuse debugger switches | `apps/desktop/src/main/main.ts`, `app-protocol.ts`, `electron-builder.yml` |
| Supply chain | Lockfile, `npm ci`, actions and images pinned by digest, Dependabot, `npm audit` and CodeQL in CI. Reproducible `app.asar` that anyone can check with `verify-release` | `.github/`, `docs/reproducible-builds.md` |
| Scams, social engineering, harassment | DMs only between people who share a server. Blocking drops DMs on the server and on LAN, and hides channel posts. Reports go to moderators, who check them against their own decrypted copy | `apps/server/src/routes/safety.ts`, `apps/desktop/src/renderer/Safety.tsx` |
| Feature abuse and denial of service | Per-account rate limits, with unauthenticated routes limited per IP. Body limits per route. Caps on invites, memberships, undelivered messages per device, blocks and open reports | `apps/server/src/limits.ts` |
| Privacy and data leaks | No email or phone. No IP logging. The vault is encrypted at rest. Security headers on every response. Tor for hiding a device's IP | `apps/server/src/app.ts`, `apps/desktop/src/main/transport.ts` |

## 6. Cryptography inventory

| Use | Construction | Where |
| --- | --- | --- |
| Device login, linking and recovery signatures | Ed25519 (`@noble/curves`) over `context\nfield\n...` payloads. Each purpose has its own context string (`SIGNING_CONTEXT`), and fields may not contain newlines | `packages/protocol/src/keys.ts` |
| Binding a Signal identity to a device | The device's Ed25519 key signs the `signalIdentity` payload. Servers and clients check it before using a bundle | `packages/signal/src/index.ts` |
| DMs | libsignal 0.106.1: PQXDH (X25519 + Kyber), Double Ratchet. One copy per recipient device | `packages/signal` |
| Channels | libsignal sender keys. Distributed over the pairwise sessions. Rotated when a member device leaves | `packages/signal`, `messenger.ts` |
| Safety numbers | For each side: SHA-512 iterated 5200 times over the version, the sorted device identity keys and the user id. 30 digits per side, sorted and joined | `packages/signal/src/safety.ts` |
| Local vault | AES-256-GCM, a random 96-bit nonce per write, the file name as AAD. The key is sealed by Electron `safeStorage`, which refuses Linux's `basic_text` fallback | `apps/desktop/src/main/vault.ts` |
| LAN links | A fresh X25519 key per link. Both sides sign both ephemeral keys and both device ids with their login key. HKDF-SHA256 derives a key per direction. AES-256-GCM with a counter nonce | `apps/desktop/src/main/lan.ts` |
| Server identity | Ed25519. Signs `serverInfo` with a nonce the client chooses | `apps/server/src/routes/server-info.ts` |
| Sealed sender | libsignal sealed sender v1. Trust root and signer are Curve25519 keys derived from the server identity secret with HKDF-SHA256. Certificates last 24 hours | `packages/signal/src/certificates.ts`, `apps/server/src/routes/sealed.ts` |
| Tokens and invite codes | 256-bit random values, stored as SHA-256 | `apps/server/src/auth.ts` |

## 7. What the server learns, by design

- Usernames, who is in which server, roles and bans.
- Which device sent a message to which account or channel, when, and how big it
  was. The exception is a sealed direct message, whose sender the server doesn't
  store. [sealed-sender.md](sealed-sender.md) lists what that does and doesn't hide.
- Whom each person has blocked.
- The content of reports: a report includes the reported text, *as the reporter
  chose to share it*, plus their note.

Findings that show the server learns more than this are what we most want.

## 8. Where we most want your attention

1. **IPC and the renderer boundary.** Can a compromised or tricked renderer:
   - reach a secret, a session token or the vault key?
   - make the main process sign something?
   - load anything other than the bundled files?

   Start with `trusted()` in `main.ts`, `app-protocol.ts`, and every schema
   in `api.ts`, `spaces.ts` and `safety.ts`.
2. **Key trust and safety numbers.** Can a malicious server:
   - add a device or key without the safety number changing?
   - make two people see matching numbers that don't cover the devices they
     actually encrypt to?
   - get a changed key accepted without the user acting?
3. **Device linking and recovery.** Can someone approve their own device, replay
   a challenge or approval, or keep access after recovery?
4. **Authorization on the server.** Role checks on space and report routes. Can
   someone read or change a server they aren't in, act above their role, or read
   the report queue without moderator rights?
5. **Block and report bypasses.** Can a blocked person still get a DM through,
   over the server or LAN? Can a report pin a message on someone who didn't send
   it?
6. **LAN delivery.** The handshake, replay or reordering of frames, and what an
   attacker on the same network can learn or inject. The multicast beacon is
   unauthenticated by design. Check that it can only cause a connection attempt.
7. **Sender-key handling.** Forged distribution messages, keys after someone
   leaves, and old messages after unblocking.
8. **Resource limits.** Ways to fill the disk, the mailbox or memory, or to slow
   the server for everyone, especially from one account or through Tor, where
   many users share an IP.
9. **Release integrity.** Does `verify-release` catch every change that matters,
   and do the fuses hold on each platform?

## 9. Known limits and planned work

None of these needs a report, but ideas for fixing them are welcome.

- Sealed sender covers direct messages only, after the first message to each person.
  Channel messages still name their sender. See [sealed-sender.md](sealed-sender.md).
- No message franking. Reports are checked against the moderator's own copy, not
  bound to the sender cryptographically.
- Unsigned release builds, and no code signing or notarization yet.
- Linux has no embedded asar integrity check. Electron doesn't support it there.
- The server identity key is in a file, not an HSM or KMS.
- Sign-up invites carry the server's identity key (`silo:<key>:<code>[:<address>]`),
  so first contact is checked. Bare codes still work and fall back to trust on
  first use, with a warning. Logging in, linking a device or recovering on a new
  device still connect by address alone.
- Starting the app with no server reachable, using only the LAN, needs an
  earlier sign-in on that device.
- Channel history is per device. A new device sees only messages sent after it
  joined.

## 10. Running it yourself

You need Node 22 and Docker, or Postgres 16.

```sh
git clone https://github.com/MichaelDamiano/silo && cd silo
npm ci
docker compose up --build              # Postgres + server on :8443
docker compose exec server node apps/server/dist/cli/create-invite.js --uses 5 --hours 72
npm run dev -w @silo/desktop           # start one or more desktop apps
```

To run several desktop apps on one machine, give each its own data folder with
`--user-data-dir`. To add Tor, run `docker compose --profile tor up`.

Tests:

```sh
export TEST_DATABASE_URL=postgres://silo:silo@localhost:5432/silo_test   # a database the tests may wipe
npm run build -w @silo/protocol && npm run build -w @silo/signal
npm run typecheck && npm test
```

To build and check a release, see [reproducible-builds.md](reproducible-builds.md).

Useful starting points:

- Server routes are in `apps/server/src/routes/`, and SQL migrations in
  `apps/server/migrations/`.
- Every request and response shape is a zod schema in `packages/protocol/src/`.
