import { hkdfSync } from 'node:crypto';
import * as S from '@signalapp/libsignal-client';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64');

/**
 * The server's sealed-sender keys, derived from its identity secret so there is
 * nothing new to store or back up. The trust root signs one server certificate,
 * whose key signs every sender certificate. Clients learn the trust root from the
 * server's signed identity, so they only trust certificates from the server they pinned.
 */
export function sealedSenderKeys(identitySecret: Uint8Array) {
  const derive = (label: string) =>
    S.PrivateKey.deserialize(new Uint8Array(hkdfSync('sha256', identitySecret, Buffer.alloc(0), `silo sealed sender ${label} v1`, 32)));
  const root = derive('root');
  const signer = derive('signer');
  const serverCert = S.ServerCertificate.new(1, signer.getPublicKey(), root);
  return { trustRoot: b64(root.getPublicKey().serialize()), signer, serverCert };
}

/**
 * A short-lived certificate saying which account and device holds this Signal identity
 * key. The username rides in the field Signal uses for a phone number, so the recipient
 * can show who wrote without asking the server, which would give the sender away.
 */
export function issueSenderCertificate(
  keys: ReturnType<typeof sealedSenderKeys>,
  sender: { userId: string; username: string; signalDeviceId: number; identityKey: string; expiresAt: number },
): string {
  const cert = S.SenderCertificate.new(
    sender.userId,
    sender.username,
    sender.signalDeviceId,
    S.PublicKey.deserialize(new Uint8Array(Buffer.from(sender.identityKey, 'base64'))),
    sender.expiresAt,
    keys.serverCert,
    keys.signer,
  );
  return b64(cert.serialize());
}
