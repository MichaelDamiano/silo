# Security policy

Silo is an early prototype and hasn't had an outside security review yet. Don't rely on it to protect anyone's safety until it has.

## Reporting a vulnerability

Please report security problems privately, not in a public issue. Use GitHub's private vulnerability reporting (the **Security** tab, then **Report a vulnerability**). Include:

- what an attacker could do, and what they need first (an account, a position on the network, access to the server)
- steps or code to reproduce it
- the commit you tested

You'll get a reply within 7 days. Once a fix is out you'll be credited, unless you'd rather not be.

## What's in scope

- The server (`apps/server`), the desktop app (`apps/desktop`), the shared protocol (`packages/protocol`), the Signal wrapper (`packages/signal`), and the relay and Tor tooling (`tools/`).
- Anything that lets someone read messages they shouldn't, impersonate a person, device or server, take over an account, get around bans, rate limits or quotas, run code on a device, or learn more about users than the design says the server learns.

Bugs in libsignal itself should go to Signal (security@signal.org).

## What the server can see, by design

The server stores and relays only ciphertext. It does see:

- usernames and server membership
- which device sent a message to which account or channel, and when
- message sizes

It doesn't log IP addresses. Reports that the server can see this metadata are known limits rather than vulnerabilities, unless it can see more than this list.

## Hardening already in place

- End-to-end encryption with libsignal: PQXDH and the Double Ratchet for DMs, sender keys for channels.
- Per-device Ed25519 login keys. There are no passwords, and session tokens and invite codes are stored only as hashes.
- Per-account rate limits. Caps on sessions per device, unused invites, memberships and undelivered messages per device.
- A server identity key, kept in a file outside the database. Clients pin it, and it signs the server's address list.
- A sandboxed Electron renderer with a strict CSP and no Node access. Every IPC message is checked in the main process.
- Base images and CI actions pinned by digest. CodeQL, `npm audit` and Dependabot run in CI.
