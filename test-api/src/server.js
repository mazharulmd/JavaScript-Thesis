import { createApp } from './app.js';
import { loadConfig } from './config.js';

const config = loadConfig();
const app = createApp(config);
const { flaws } = app.locals.ctx;

const server = app.listen(config.port, config.host, () => {
  console.log(`[test-api] listening on http://${config.host}:${config.port} (flaws: ${flaws.mode}, ${flaws.list().length} enabled, benchmarkMode: ${config.benchmarkMode})`);
  console.log('[test-api] WARNING: intentionally vulnerable. Run only in an isolated local environment.');
});

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.close(() => process.exit(0)));
}
