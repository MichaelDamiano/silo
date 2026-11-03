import { buildApp } from './app.js';
import { loadConfig } from './config.js';
import { createPool, migrate } from './db.js';

const config = loadConfig();
const db = createPool(config.databaseUrl);
const applied = await migrate(db);
const app = await buildApp(config, db);
if (applied.length) app.log.info({ applied }, 'applied migrations');
await app.listen({ port: config.port, host: config.host });

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, async () => {
    await app.close();
    await db.end();
    process.exit(0);
  });
}
