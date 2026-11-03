import { loadConfig } from '../config.js';
import { createPool, migrate } from '../db.js';

const db = createPool(loadConfig().databaseUrl);
const applied = await migrate(db);
console.log(applied.length ? `Applied: ${applied.join(', ')}` : 'Database is up to date.');
await db.end();
