import { randomBytes } from 'node:crypto';
import type { PrismaClient, Role } from '@prisma/client';
import { hashPassword } from './password.js';
import { ConflictError, revokeAllSessions, toPublic, type PublicUser } from './auth.js';

export class NotFoundError extends Error {
  readonly statusCode = 404;
  constructor(id: string) {
    super(`User ${id} not found`);
    this.name = 'NotFoundError';
  }
}

export class SelfLockoutError extends Error {
  readonly statusCode = 409;
  constructor(message: string) {
    super(message);
    this.name = 'SelfLockoutError';
  }
}

export async function listUsers(
  db: PrismaClient,
  filter: { q?: string; role?: Role; active?: boolean; cursor?: string; limit?: number },
): Promise<{ items: PublicUser[]; nextCursor: string | null; total: number }> {
  const take = Math.min(filter.limit ?? 50, 200);
  const where = {
    ...(filter.role ? { role: filter.role } : {}),
    ...(filter.active !== undefined ? { active: filter.active } : {}),
    ...(filter.q
      ? {
          OR: [
            { email: { contains: filter.q, mode: 'insensitive' as const } },
            { name: { contains: filter.q, mode: 'insensitive' as const } },
            { phone: { contains: filter.q } },
          ],
        }
      : {}),
  };
  const [rows, total] = await Promise.all([
    db.user.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: take + 1,
      ...(filter.cursor ? { cursor: { id: filter.cursor }, skip: 1 } : {}),
    }),
    db.user.count({ where }),
  ]);
  const more = rows.length > take;
  const items = (more ? rows.slice(0, take) : rows).map(toPublic);
  return { items, nextCursor: more ? items[items.length - 1]!.id : null, total };
}

export async function userSummary(db: PrismaClient): Promise<Record<string, number>> {
  const grouped = await db.user.groupBy({ by: ['role'], where: { active: true }, _count: { _all: true } });
  const out: Record<string, number> = { ADMIN: 0, DISPATCHER: 0, SUPPORT: 0, DRIVER: 0, CUSTOMER: 0 };
  for (const g of grouped) out[g.role] = g._count._all;
  return out;
}

// Readable but strong: 4 groups of 5 from a 32-char alphabet is 100 bits.
const tempPassword = (): string => {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = randomBytes(20);
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
  return [0, 5, 10, 15].map((i) => chars.slice(i, i + 5).join('')).join('-');
};

/**
 * Admin-created accounts. When no password is given a temporary one is
 * generated and returned exactly once - it is never stored in plain text and
 * cannot be fetched again.
 */
export async function createUser(
  db: PrismaClient,
  input: { email: string; name: string; role: Role; phone?: string; password?: string },
): Promise<{ user: PublicUser; temporaryPassword?: string }> {
  const email = input.email.toLowerCase();
  if (await db.user.findUnique({ where: { email } })) throw new ConflictError('Email already registered');
  const password = input.password ?? tempPassword();
  const user = await db.user.create({
    data: {
      email,
      name: input.name,
      role: input.role,
      ...(input.phone ? { phone: input.phone } : {}),
      passwordHash: await hashPassword(password),
    },
  });
  return { user: toPublic(user), ...(input.password ? {} : { temporaryPassword: password }) };
}

/**
 * Admin-issued reset for a forgotten password: a new temporary password,
 * returned once, and every session ended so the old credentials stop working.
 */
export async function resetPassword(db: PrismaClient, id: string): Promise<{ temporaryPassword: string; email: string }> {
  const user = await db.user.findUnique({ where: { id } });
  if (!user) throw new NotFoundError(id);
  const password = tempPassword();
  await db.user.update({ where: { id }, data: { passwordHash: await hashPassword(password) } });
  await revokeAllSessions(db, id);
  return { temporaryPassword: password, email: user.email };
}

export interface UserPatch {
  name?: string;
  phone?: string | null;
  role?: Role;
  active?: boolean;
}

/**
 * Role and status changes end the user's sessions, so the change bites at the
 * next refresh (at most one access-token lifetime) instead of at the next
 * voluntary login.
 */
export async function updateUser(
  db: PrismaClient,
  actorId: string,
  id: string,
  patch: UserPatch,
): Promise<{ user: PublicUser; before: PublicUser; sessionsRevoked: number }> {
  const current = await db.user.findUnique({ where: { id } });
  if (!current) throw new NotFoundError(id);

  // An admin demoting or disabling themselves can leave nobody able to undo it.
  if (id === actorId && ((patch.role && patch.role !== 'ADMIN') || patch.active === false)) {
    throw new SelfLockoutError('You cannot remove your own admin access');
  }

  const user = await db.user.update({
    where: { id },
    data: {
      ...(patch.name !== undefined ? { name: patch.name } : {}),
      ...(patch.phone !== undefined ? { phone: patch.phone } : {}),
      ...(patch.role !== undefined ? { role: patch.role } : {}),
      ...(patch.active !== undefined ? { active: patch.active } : {}),
    },
  });

  const privilegeChanged =
    (patch.role !== undefined && patch.role !== current.role) ||
    (patch.active === false && current.active);
  const sessionsRevoked = privilegeChanged ? await revokeAllSessions(db, id) : 0;

  return { user: toPublic(user), before: toPublic(current), sessionsRevoked };
}

export async function updateProfile(
  db: PrismaClient,
  id: string,
  patch: { name?: string; phone?: string | null },
): Promise<PublicUser> {
  const user = await db.user.update({
    where: { id },
    data: {
      ...(patch.name !== undefined ? { name: patch.name } : {}),
      ...(patch.phone !== undefined ? { phone: patch.phone } : {}),
    },
  });
  return toPublic(user);
}
