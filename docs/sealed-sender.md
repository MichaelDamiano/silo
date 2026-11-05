# Sealed sender

Silo's direct messages normally reach the server signed in, so the server knows who sent each one. With
sealed sender, the server stores a direct message without knowing who wrote it. Only the recipient
learns that, from inside the encryption. This follows Signal's design, using libsignal's own
sealed sender code.

## How it works

1. **Trust root.** The server derives two Curve25519 keys from its identity secret with HKDF (labels
   `silo sealed sender root v1` and `… signer v1`). The root signs a server certificate for the
   signer. The root's public key is published as `sealedSenderRoot` in the signed `/v1/server-info`
   answer, so apps only trust certificates from the server whose identity key they pinned. Nothing
   new is stored or backed up.
2. **Sender certificates.** `GET /v1/certificate` (signed in) returns a certificate for 24 hours that
   names the account, its username, the device's Signal device id and its Signal identity key. Apps
   fetch it ahead of time, not right before a send.
3. **Access keys.** Each account has a random 16-byte access key (`GET /v1/access-key`), shared by
   all of its devices. Every direct message carries the sender's key inside the encryption. Once
   you've received a message from someone, you hold their key.
4. **Sending.** With the recipient's key, the app encrypts each copy with
   `sealedSenderEncrypt` and posts them to `POST /v1/sealed/:userId/messages` **without signing in**,
   with the key in the `silo-access-key` header, on a connection no other request uses (through
   Tor, on a separate circuit). The server checks the key and the device list and stores the
   copies with no sender (`message_type = 6`, `sender_user` and `sender_device` NULL).
5. **Receiving.** The recipient opens it with `sealedSenderDecrypt`. libsignal checks that the
   certificate chains to the trust root, hasn't expired, and names the identity key that
   actually encrypted the message.
6. **No key yet, or a wrong key.** The first message to someone, or one after they replaced their
   key, goes the normal signed-in way. A wrong key and an unknown account get the same 401.

## Blocking

The server can't drop a sealed message from someone you blocked, because it doesn't know who sent
it. So blocking someone also replaces your access key (`POST /v1/access-key/rotate`). Their sealed
sends then fail, their app falls back to a signed-in send, and the server drops that one as before.
Your app also hides anything from a blocked person that still gets through. Everyone else gets your
new key with your next message to them, and writes to you the normal way until then.

## What it does and doesn't hide

Hidden from the server's database and logs: the sender of a sealed direct message.

Not hidden:

- **The recipient**, the time and the size.
- **Your IP address.** A sealed send uses a fresh connection, but without Tor it still comes from
  your IP, which the server could match against your signed-in connections while it is running.
  Turn on "Send everything through Tor" to close that gap.
- **Copies for your other devices.** A sealed send can't carry them, so they follow as a signed-in
  send to yourself. The server sees that you sent something at that moment, though not to whom.
  Someone watching the live server could match that to the sealed message by time.
- **Fetching keys for a device you've never written to.** That request is signed in. Device lists
  otherwise come from the background directory refresh, not from a lookup just before sending.
- **Channel messages and sender-key handoffs**, which still name their sender. A channel message
  goes to everyone in the channel, who need to know who wrote it anyway.
- **The first message** to each person, which goes signed in because you don't have their key yet.

The access key only decides who may leave sealed messages in a mailbox. The server stores it as is,
so all of an account's devices can read it. It protects nothing the server couldn't do itself.

## Code

- `packages/signal/src/certificates.ts`: key derivation and certificates.
- `packages/signal/src/index.ts`: `sealedEncrypt` and `sealedDecrypt`.
- `apps/server/src/routes/sealed.ts`: certificate, access key and sealed delivery routes.
- `apps/desktop/src/main/messenger.ts`: `sendSealed`, `receiveSealed`, `rotateAccessKey`.
- `apps/desktop/src/main/transport.ts`: isolated requests.
