import { describe, it, expect, vi, beforeAll } from 'vitest';
import { initKeys } from '../src/domain/tokens.js';
import { hashPassword } from '../src/domain/password.js';
import { login, refresh, logout, register, AuthError, ConflictError } from '../src/domain/auth.js';

beforeAll(async () => { await initKeys(); });

const user = (over: Record<string, unknown> = {}) => ({
  id: 'u1', email: 'a@b.c', name: 'Sam', role: 'CUSTOMER', active: true,
  passwordHash: '', createdAt: new Date(), updatedAt: new Date(), ...over,
});

const makeDb = (opts: { user?: unknown; refreshRow?: unknown } = {}) => {
  const rtUpdate = vi.fn(async () => ({}));
  const rtUpdateMany = vi.fn(async () => ({ count: 1 }));
  const rtCreate = vi.fn(async () => ({}));
  const db = {
    user: {
      findUnique: vi.fn(async () => ('user' in opts ? opts.user : null)),
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => user(data)),
    },
    refreshToken: {
      create: rtCreate,
      update: rtUpdate,
      updateMany: rtUpdateMany,
      findUnique: vi.fn(async () => ('refreshRow' in opts ? opts.refreshRow : null)),
    },
  } as never;
  return { db, rtUpdate, rtUpdateMany, rtCreate };
};

describe('register', () => {
  it('rejects a duplicate email', async () => {
    const { db } = makeDb({ user: user() });
    await expect(register(db, { email: 'a@b.c', password: 'x'.repeat(12), name: 'Sam' }))
      .rejects.toBeInstanceOf(ConflictError);
  });

  it('lowercases the email so casing cannot create duplicates', async () => {
    const { db } = makeDb();
    const r = await register(db, { email: 'SAM@Example.COM', password: 'x'.repeat(12), name: 'Sam' });
    expect(r.user.email).toBe('sam@example.com');
  });

  it('never returns the password hash', async () => {
    const { db } = makeDb();
    const r = await register(db, { email: 'a@b.c', password: 'x'.repeat(12), name: 'Sam' });
    expect(r.user).not.toHaveProperty('passwordHash');
  });
});

describe('login', () => {
  it('issues a token pair for valid credentials', async () => {
    const { db } = makeDb({ user: user({ passwordHash: await hashPassword('hunter2hunter2') }) });
    const r = await login(db, { email: 'a@b.c', password: 'hunter2hunter2' });
    expect(r.tokens.accessToken).toBeTruthy();
    expect(r.tokens.refreshToken).toBeTruthy();
  });

  it('rejects a wrong password', async () => {
    const { db } = makeDb({ user: user({ passwordHash: await hashPassword('hunter2hunter2') }) });
    await expect(login(db, { email: 'a@b.c', password: 'wrongwrongwrong' }))
      .rejects.toBeInstanceOf(AuthError);
  });

  // Same error and same work either way, so responses cannot be used to
  // enumerate which emails are registered.
  it('gives the same error for an unknown email as for a wrong password', async () => {
    const { db: noUser } = makeDb();
    const { db: withUser } = makeDb({ user: user({ passwordHash: await hashPassword('hunter2hunter2') }) });

    const a = await login(noUser, { email: 'nobody@b.c', password: 'whatever12345' }).catch((e: Error) => e);
    const b = await login(withUser, { email: 'a@b.c', password: 'wrongwrongwrong' }).catch((e: Error) => e);
    expect((a as Error).message).toBe((b as Error).message);
  });

  it('refuses a disabled account', async () => {
    const { db } = makeDb({ user: user({ active: false, passwordHash: await hashPassword('hunter2hunter2') }) });
    await expect(login(db, { email: 'a@b.c', password: 'hunter2hunter2' }))
      .rejects.toThrow(/disabled/);
  });
});

describe('refresh rotation', () => {
  const row = (over: Record<string, unknown> = {}) => ({
    id: 'rt1', userId: 'u1', familyId: 'fam1', tokenHash: 'h',
    expiresAt: new Date(Date.now() + 86_400_000), revokedAt: null,
    user: user(), ...over,
  });

  it('revokes the presented token and issues a new one', async () => {
    const { db, rtUpdate, rtCreate } = makeDb({ refreshRow: row() });
    const tokens = await refresh(db, 'anything');
    expect(tokens.accessToken).toBeTruthy();
    expect((rtUpdate.mock.calls[0]![0] as { data: { revokedAt: Date } }).data.revokedAt).toBeInstanceOf(Date);
    expect(rtCreate).toHaveBeenCalled();
  });

  it('keeps the new token in the same family', async () => {
    const { db, rtCreate } = makeDb({ refreshRow: row() });
    await refresh(db, 'anything');
    expect((rtCreate.mock.calls[0]![0] as { data: { familyId: string } }).data.familyId).toBe('fam1');
  });

  /**
   * Reuse detection. A revoked token being presented means it leaked - the
   * legitimate client already rotated it. Revoking the whole family logs the
   * attacker out along with the victim, forcing a real login.
   */
  it('revokes the entire family when a revoked token is replayed', async () => {
    const { db, rtUpdateMany } = makeDb({ refreshRow: row({ revokedAt: new Date() }) });
    await expect(refresh(db, 'stolen')).rejects.toThrow(/reuse detected/);
    expect(rtUpdateMany).toHaveBeenCalledWith(expect.objectContaining({
      where: { familyId: 'fam1', revokedAt: null },
    }));
  });

  it('rejects an expired token', async () => {
    const { db } = makeDb({ refreshRow: row({ expiresAt: new Date(Date.now() - 1000) }) });
    await expect(refresh(db, 'old')).rejects.toThrow(/expired/);
  });

  it('rejects an unknown token', async () => {
    const { db } = makeDb();
    await expect(refresh(db, 'nope')).rejects.toBeInstanceOf(AuthError);
  });

  it('refuses to refresh for a disabled account', async () => {
    const { db } = makeDb({ refreshRow: row({ user: user({ active: false }) }) });
    await expect(refresh(db, 'x')).rejects.toThrow(/disabled/);
  });
});

describe('logout', () => {
  it('does not error on an unknown token', async () => {
    const { db } = makeDb();
    await expect(logout(db, 'never-existed')).resolves.toBeUndefined();
  });
});
