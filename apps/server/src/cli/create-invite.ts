import { parseArgs } from 'node:util';
import { formatInvite } from '@silo/protocol';
import { loadConfig } from '../config.js';
import { createPool, migrate } from '../db.js';
import { createInvite } from '../invites.js';
import { serverIdentity } from '../routes/server-info.js';

// Bootstraps the first invite, since nobody exists yet to create one in the app.
const { values } = parseArgs({
  options: { uses: { type: 'string', default: '1' }, hours: { type: 'string', default: '72' } },
});
const config = loadConfig();
const db = createPool(config.databaseUrl);
await migrate(db);
const invite = await createInvite(db, {
  createdBy: null,
  maxUses: Number(values.uses),
  expiresInHours: Number(values.hours),
});
const { publicKey } = await serverIdentity(db, config.serverKeyFile);
// The full invite carries the server's key, so the new user's app refuses an impostor on first contact.
console.log(`Invite: ${formatInvite({ code: invite.code, serverKey: publicKey, address: config.publicUrls[0] })}`);
console.log(`Invite code: ${invite.code}`);
console.log(`Uses: ${invite.maxUses}, expires ${invite.expiresAt.toISOString()}`);
await db.end();
