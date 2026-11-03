import { parseArgs } from 'node:util';
import { loadConfig } from '../config.js';
import { createPool, migrate } from '../db.js';
import { createInvite } from '../invites.js';

// Bootstraps the first invite, since nobody exists yet to create one in the app.
const { values } = parseArgs({
  options: { uses: { type: 'string', default: '1' }, hours: { type: 'string', default: '72' } },
});
const db = createPool(loadConfig().databaseUrl);
await migrate(db);
const invite = await createInvite(db, {
  createdBy: null,
  maxUses: Number(values.uses),
  expiresInHours: Number(values.hours),
});
console.log(`Invite code: ${invite.code}`);
console.log(`Uses: ${invite.maxUses}, expires ${invite.expiresAt.toISOString()}`);
await db.end();
