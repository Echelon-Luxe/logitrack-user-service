import { buildApp, setReady, SERVICE_NAME } from './app.js';
import { initKeys } from './domain/tokens.js';
import { pingDb } from './db/client.js';

const PORT = Number(process.env['PORT'] ?? 3001);
const app = buildApp();

async function main(): Promise<void> {
  await initKeys();
  if (!process.env['JWT_PRIVATE_KEY']) {
    // Each replica would otherwise generate its own key, so a token issued by
    // one pod fails verification everywhere else.
    app.log.warn('JWT_PRIVATE_KEY not set; generated an ephemeral key pair (single-instance only)');
  }

  await app.listen({ port: PORT, host: '0.0.0.0' });

  if (!(await pingDb())) {
    // Stay up but un-ready rather than crash-loop through a DB outage.
    app.log.error('database unreachable at startup; staying un-ready');
  }

  setReady(true);
  app.log.info({ service: SERVICE_NAME, port: PORT }, 'service started');
}

let shuttingDown = false;
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.log.info({ signal }, 'shutting down');
    // Fail readiness before closing so the pod leaves Service endpoints first.
    setReady(false);
    void app.close().then(() => process.exit(0));
  });
}

main().catch((err: unknown) => {
  app.log.error({ err }, 'failed to start');
  process.exit(1);
});
