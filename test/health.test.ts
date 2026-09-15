import { describe, it, expect, afterEach, vi, beforeAll } from 'vitest';

const pingDb = vi.fn<() => Promise<boolean>>();
vi.mock('../src/db/client.js', () => ({ pingDb: () => pingDb(), prisma: {} }));

const { initKeys } = await import('../src/domain/tokens.js');
const { buildApp, setReady } = await import('../src/app.js');

beforeAll(async () => { await initKeys(); });

describe('health endpoints', () => {
  afterEach(() => { setReady(false); pingDb.mockReset(); });

  it('liveness is up even when the database is unreachable', async () => {
    pingDb.mockResolvedValue(false);
    const app = buildApp();
    expect((await app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200);
    await app.close();
  });

  it('readiness is 503 before the service marks itself ready', async () => {
    pingDb.mockResolvedValue(true);
    const app = buildApp();
    expect((await app.inject({ method: 'GET', url: '/readyz' })).statusCode).toBe(503);
    await app.close();
  });

  it('readiness is 200 when ready, keys loaded and the database answers', async () => {
    pingDb.mockResolvedValue(true);
    const app = buildApp();
    setReady(true);
    const res = await app.inject({ method: 'GET', url: '/readyz' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ db: true, keys: true });
    await app.close();
  });

  it('serves a JWKS containing only public key material', async () => {
    const app = buildApp();
    const res = await app.inject({ method: 'GET', url: '/.well-known/jwks.json' });
    expect(res.statusCode).toBe(200);
    const k = res.json().keys[0];
    expect(k.kty).toBe('RSA');
    expect(k.d).toBeUndefined();
    await app.close();
  });

  it('exposes the refresh-reuse metric', async () => {
    const app = buildApp();
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.body).toContain('auth_refresh_reuse_detected_total');
    expect(res.body).toContain('auth_login_attempts_total');
    await app.close();
  });
});
