import { Registry, collectDefaultMetrics, Counter } from 'prom-client';

export const registry = new Registry();
registry.setDefaultLabels({ service: 'logitrack-user-service' });
collectDefaultMetrics({ register: registry });

export const loginAttempts = new Counter({
  name: 'auth_login_attempts_total',
  help: 'Login attempts',
  labelNames: ['result'] as const,
  registers: [registry],
});

export const tokensIssued = new Counter({
  name: 'auth_tokens_issued_total',
  help: 'Access tokens issued',
  labelNames: ['grant'] as const,
  registers: [registry],
});

// A spike here means a stolen refresh token was replayed.
export const refreshReuseDetected = new Counter({
  name: 'auth_refresh_reuse_detected_total',
  help: 'Revoked refresh tokens presented again, indicating a leak',
  registers: [registry],
});

export const httpRequests = new Counter({
  name: 'http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status'] as const,
  registers: [registry],
});
