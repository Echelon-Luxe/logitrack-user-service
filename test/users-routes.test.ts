import { describe, it, expect, vi, beforeEach } from 'vitest';

// Route-level authorisation: the gateway already gates /users, these prove the
// service holds the line on its own if a request ever reaches it directly.
const db = {
  user: {
    findMany: vi.fn(async () => []),
    count: vi.fn(async () => 0),
    findUnique: vi.fn(async () => null as unknown),
    update: vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'u2', email: 'b@c.d', name: 'B', role: 'CUSTOMER', active: true, createdAt: new Date(), ...data })),
  },
  refreshToken: { updateMany: vi.fn(async () => ({ count: 3 })) },
  auditLog: { create: vi.fn(async () => ({})) },
};
vi.mock('../src/db/client.js', () => ({ prisma: db, pingDb: async () => true }));

const { buildApp } = await import('../src/app.js');

const as = (role: string, id = 'admin-1') => ({ 'x-user-id': id, 'x-user-role': role, 'x-user-email': `${role.toLowerCase()}@x.y` });
const target = '00000000-0000-4000-8000-000000000099';

beforeEach(() => { vi.clearAllMocks(); });

describe('/users authorisation', () => {
  it('lets staff list users but not customers or drivers', async () => {
    const app = buildApp();
    for (const [role, code] of [['ADMIN', 200], ['DISPATCHER', 200], ['SUPPORT', 200], ['CUSTOMER', 403], ['DRIVER', 403]] as const) {
      const res = await app.inject({ method: 'GET', url: '/users', headers: as(role) });
      expect(res.statusCode, role).toBe(code);
    }
    await app.close();
  });

  it('401s without gateway identity', async () => {
    const app = buildApp();
    expect((await app.inject({ method: 'GET', url: '/users' })).statusCode).toBe(401);
    expect((await app.inject({ method: 'GET', url: '/auth/me', headers: { 'x-user-id': 'u1' } })).statusCode).toBe(401);
    await app.close();
  });

  it('lets only ADMIN change roles', async () => {
    const app = buildApp();
    const res = await app.inject({ method: 'PATCH', url: `/users/${target}`, headers: as('DISPATCHER'), payload: { role: 'ADMIN' } });
    expect(res.statusCode).toBe(403);
    expect(db.user.update).not.toHaveBeenCalled();
    await app.close();
  });

  // The change must bite at the next refresh, not the next voluntary login.
  it('revokes sessions and writes an audit row when a role changes', async () => {
    db.user.findUnique.mockResolvedValueOnce({ id: target, email: 'b@c.d', name: 'B', role: 'CUSTOMER', active: true, createdAt: new Date() });
    const app = buildApp();
    const res = await app.inject({ method: 'PATCH', url: `/users/${target}`, headers: as('ADMIN'), payload: { role: 'DISPATCHER' } });
    expect(res.statusCode).toBe(200);
    expect(res.json().sessionsRevoked).toBe(3);
    expect(db.auditLog.create).toHaveBeenCalledWith(expect.objectContaining({
      data: expect.objectContaining({ action: 'user.role_changed', targetId: target }),
    }));
    await app.close();
  });

  it('stops an admin from demoting themselves', async () => {
    db.user.findUnique.mockResolvedValueOnce({ id: 'admin-1', email: 'a@b.c', name: 'A', role: 'ADMIN', active: true, createdAt: new Date() });
    const app = buildApp();
    const res = await app.inject({ method: 'PATCH', url: '/users/00000000-0000-4000-8000-000000000001', headers: as('ADMIN', '00000000-0000-4000-8000-000000000001'), payload: { active: false } });
    expect(res.statusCode).toBe(409);
    await app.close();
  });

  it('lets only ADMIN reset a password, and the reset ends every session', async () => {
    const app = buildApp();
    expect((await app.inject({ method: 'POST', url: `/users/${target}/reset-password`, headers: as('SUPPORT') })).statusCode).toBe(403);
    db.user.findUnique.mockResolvedValueOnce({ id: target, email: 'b@c.d', name: 'B', role: 'CUSTOMER', active: true, createdAt: new Date() });
    const res = await app.inject({ method: 'POST', url: `/users/${target}/reset-password`, headers: as('ADMIN') });
    expect(res.statusCode).toBe(200);
    expect(res.json().temporaryPassword).toMatch(/^[a-z0-9]{5}(-[a-z0-9]{5}){3}$/);
    expect(db.refreshToken.updateMany).toHaveBeenCalled();
    await app.close();
  });

  it('rejects role and active in a self-service profile update', async () => {
    const app = buildApp();
    const res = await app.inject({ method: 'PATCH', url: '/auth/me', headers: as('CUSTOMER', 'c1'), payload: { role: 'ADMIN' } });
    expect(res.statusCode).toBe(400);
    await app.close();
  });
});
