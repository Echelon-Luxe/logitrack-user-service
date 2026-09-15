import Fastify, { type FastifyInstance } from 'fastify';
import { registry, httpRequests } from './metrics.js';
import { authRoutes } from './routes/auth.js';
import { registerErrorHandler } from './errors.js';
import { pingDb } from './db/client.js';
import { keysReady } from './domain/tokens.js';

export const SERVICE_NAME = 'logitrack-user-service';

let ready = false;
export const setReady = (v: boolean): void => { ready = v; };

export function buildApp(): FastifyInstance {
  const app = Fastify({
    logger: {
      level: process.env['LOG_LEVEL'] ?? 'info',
      // Passwords and tokens must never reach the log collector.
      redact: {
        paths: ['req.body.password', 'req.body.refreshToken', 'req.headers.authorization'],
        censor: '[redacted]',
      },
    },
    trustProxy: true,
  });

  app.addHook('onResponse', (req, reply, done) => {
    httpRequests.inc({
      method: req.method,
      route: req.routeOptions.url ?? 'unknown',
      status: String(reply.statusCode),
    });
    done();
  });

  // Never checks dependencies: failing liveness kills the container.
  app.get('/healthz', () => ({ status: 'ok', service: SERVICE_NAME }));

  app.get('/readyz', async (_req, reply) => {
    if (!ready) return reply.code(503).send({ status: 'not-ready', service: SERVICE_NAME });
    // Signing keys are checked too: without them no token can be issued, so
    // serving traffic would only produce 500s.
    if (!keysReady()) {
      return reply.code(503).send({ status: 'not-ready', service: SERVICE_NAME, keys: false });
    }
    const db = await pingDb();
    if (!db) return reply.code(503).send({ status: 'not-ready', service: SERVICE_NAME, db: false });
    return { status: 'ready', service: SERVICE_NAME, db: true, keys: true };
  });

  app.get('/metrics', async (_req, reply) => {
    reply.header('Content-Type', registry.contentType);
    return registry.metrics();
  });

  registerErrorHandler(app);
  void app.register(authRoutes);

  return app;
}
