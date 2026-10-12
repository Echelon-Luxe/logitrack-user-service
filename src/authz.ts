import { timingSafeEqual } from 'node:crypto';
import type { FastifyRequest } from 'fastify';

// Identity and role checks for requests arriving through the gateway.
//
// The gateway verifies the JWT and forwards the subject as x-user-* headers;
// this module turns those into an Identity and enforces the permission matrix
// in logitrack-infrastructure/docs/rbac.md. The same file lives in every
// backend - the services are separate repos and share no package, and a dozen
// lines duplicated beats a cross-repo dependency for something this small.

export const ROLES = ['ADMIN', 'DISPATCHER', 'SUPPORT', 'DRIVER', 'CUSTOMER'] as const;
export type Role = (typeof ROLES)[number];

// Back-office roles: see every record, own none.
export const STAFF: readonly Role[] = ['ADMIN', 'DISPATCHER', 'SUPPORT'];
// Staff who may change operational state. SUPPORT is read-only.
export const OPERATORS: readonly Role[] = ['ADMIN', 'DISPATCHER'];

export interface Identity {
  userId: string;
  role: Role;
  email: string;
  name: string;
}

export class UnauthorizedError extends Error {
  readonly statusCode = 401;
  constructor(message = 'Unauthorized') {
    super(message);
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends Error {
  readonly statusCode = 403;
  constructor(message = 'You do not have permission to do that') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

const header = (req: FastifyRequest, name: string): string | undefined => {
  const v = req.headers[name];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
};

const sameSecret = (a: string, b: string): boolean => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/**
 * When INTERNAL_TOKEN is set, identity headers are only believed alongside it.
 * Without this, anything that can reach a backend directly - another pod, a
 * misrouted ingress - could claim to be any user by sending x-user-id.
 */
export function fromGateway(req: FastifyRequest): boolean {
  const expected = process.env['INTERNAL_TOKEN'];
  if (!expected) return true;
  const presented = header(req, 'x-internal-token');
  return presented !== undefined && sameSecret(presented, expected);
}

export function identity(req: FastifyRequest): Identity {
  if (!fromGateway(req)) throw new UnauthorizedError();
  const userId = header(req, 'x-user-id');
  const role = header(req, 'x-user-role');
  if (!userId || !role || !(ROLES as readonly string[]).includes(role)) {
    throw new UnauthorizedError();
  }
  const rawName = header(req, 'x-user-name');
  let name = '';
  try {
    name = rawName ? decodeURIComponent(rawName) : '';
  } catch {
    name = rawName ?? '';
  }
  return { userId, role: role as Role, email: header(req, 'x-user-email') ?? '', name };
}

export const hasRole = (id: Identity, roles: readonly Role[]): boolean => roles.includes(id.role);

export function requireRole(id: Identity, roles: readonly Role[]): void {
  if (!hasRole(id, roles)) throw new ForbiddenError();
}

export const isStaff = (id: Identity): boolean => hasRole(id, STAFF);

/**
 * Service-to-service call carrying the internal token. The caller acts as a
 * SYSTEM principal, never as the end user, so a backend cannot be tricked into
 * widening a user's access by relaying their request.
 */
export async function internalFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = process.env['INTERNAL_TOKEN'];
  if (token) headers.set('x-internal-token', token);
  headers.set('x-user-id', 'system');
  headers.set('x-user-role', 'ADMIN');
  headers.set('x-user-email', 'system@logitrack.internal');
  if (init.body && !headers.has('content-type')) headers.set('content-type', 'application/json');
  return fetch(url, { ...init, headers, signal: init.signal ?? AbortSignal.timeout(5_000) });
}
