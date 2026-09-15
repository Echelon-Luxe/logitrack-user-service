import { randomUUID } from 'node:crypto';
import type { PrismaClient, User } from '@prisma/client';
import { hashPassword, verifyPassword } from './password.js';
import {
  signAccessToken, newRefreshToken, hashRefreshToken, refreshExpiry,
} from './tokens.js';

export class AuthError extends Error {
  readonly statusCode = 401;
  constructor(message = 'Invalid credentials') {
    super(message);
    this.name = 'AuthError';
  }
}

export class ConflictError extends Error {
  readonly statusCode = 409;
  constructor(message: string) {
    super(message);
    this.name = 'ConflictError';
  }
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export type PublicUser = Pick<User, 'id' | 'email' | 'name' | 'role' | 'active' | 'createdAt'>;

export const toPublic = (u: User): PublicUser => ({
  id: u.id, email: u.email, name: u.name, role: u.role, active: u.active, createdAt: u.createdAt,
});

async function issue(db: PrismaClient, user: User, familyId?: string): Promise<TokenPair> {
  const accessToken = await signAccessToken({ sub: user.id, email: user.email, role: user.role });
  const { token, hash } = newRefreshToken();
  await db.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: hash,
      familyId: familyId ?? randomUUID(),
      expiresAt: refreshExpiry(),
    },
  });
  return { accessToken, refreshToken: token, expiresIn: 900 };
}

export async function register(
  db: PrismaClient,
  input: { email: string; password: string; name: string; role?: 'CUSTOMER' | 'DRIVER' | 'ADMIN' },
): Promise<{ user: PublicUser; tokens: TokenPair }> {
  const email = input.email.toLowerCase();
  if (await db.user.findUnique({ where: { email } })) {
    throw new ConflictError('Email already registered');
  }
  const user = await db.user.create({
    data: {
      email,
      name: input.name,
      passwordHash: await hashPassword(input.password),
      role: input.role ?? 'CUSTOMER',
    },
  });
  return { user: toPublic(user), tokens: await issue(db, user) };
}

export async function login(
  db: PrismaClient,
  input: { email: string; password: string },
): Promise<{ user: PublicUser; tokens: TokenPair }> {
  const user = await db.user.findUnique({ where: { email: input.email.toLowerCase() } });

  // Hash even when the user does not exist, so response time does not reveal
  // which emails are registered.
  const stored = user?.passwordHash ?? 'scrypt$65536$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAA';
  const ok = await verifyPassword(input.password, stored);

  if (!user || !ok) throw new AuthError();
  if (!user.active) throw new AuthError('Account is disabled');

  return { user: toPublic(user), tokens: await issue(db, user) };
}

/**
 * Rotating refresh: the presented token is revoked and a new one issued.
 *
 * If an already-revoked token is presented, it leaked - the legitimate client
 * rotated it, so anyone still holding the old value is an attacker. The whole
 * family is revoked, forcing a real login.
 */
export async function refresh(db: PrismaClient, presented: string): Promise<TokenPair> {
  const hash = hashRefreshToken(presented);
  const row = await db.refreshToken.findUnique({ where: { tokenHash: hash }, include: { user: true } });
  if (!row) throw new AuthError('Invalid refresh token');

  if (row.revokedAt) {
    await db.refreshToken.updateMany({
      where: { familyId: row.familyId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    throw new AuthError('Refresh token reuse detected; session revoked');
  }

  if (row.expiresAt < new Date()) throw new AuthError('Refresh token expired');
  if (!row.user.active) throw new AuthError('Account is disabled');

  await db.refreshToken.update({ where: { id: row.id }, data: { revokedAt: new Date() } });
  return issue(db, row.user, row.familyId);
}

export async function logout(db: PrismaClient, presented: string): Promise<void> {
  const hash = hashRefreshToken(presented);
  // updateMany, not update: logging out with an unknown token is not an error.
  await db.refreshToken.updateMany({
    where: { tokenHash: hash, revokedAt: null },
    data: { revokedAt: new Date() },
  });
}

export async function getUser(db: PrismaClient, id: string): Promise<PublicUser | null> {
  const u = await db.user.findUnique({ where: { id } });
  return u ? toPublic(u) : null;
}
