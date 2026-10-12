import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../db/client.js';
import { register, login, refresh, logout, getUser, changePassword, AuthError } from '../domain/auth.js';
import { updateProfile } from '../domain/users.js';
import { audit } from '../domain/audit.js';
import { identity } from '../authz.js';
import { jwks } from '../domain/tokens.js';
import { loginAttempts, tokensIssued, refreshReuseDetected } from '../metrics.js';

const Credentials = z.object({
  email: z.string().email().max(254),
  // Length is the dominant factor in password strength; a composition rule
  // mostly teaches people to write Passw0rd!.
  password: z.string().min(12).max(200),
});

const RefreshBody = z.object({ refreshToken: z.string().min(1) });

// Loose on purpose: formats vary by country and the UI only uses it for tel: links.
export const Phone = z.string().trim().min(5).max(32).regex(/^[+\d][\d\s().-]+$/, 'Invalid phone number');

export async function authRoutes(app: FastifyInstance): Promise<void> {
  // The gateway fetches this to verify tokens. Only the PUBLIC key is here.
  app.get('/.well-known/jwks.json', async (_req, reply) => {
    reply.header('cache-control', 'public, max-age=300');
    return jwks();
  });

  app.post('/auth/register', async (req, reply) => {
    const body = Credentials.extend({
      name: z.string().min(1).max(120),
      phone: Phone.optional(),
      // Self-service registration cannot grant a staff role; that would be
      // privilege escalation by request body. Staff are created by an admin.
      role: z.enum(['CUSTOMER', 'DRIVER']).optional(),
    }).parse(req.body);

    // exactOptionalPropertyTypes: an explicit undefined is not an omitted key.
    const { role, phone, ...rest } = body;
    const result = await register(prisma, {
      ...rest,
      ...(role !== undefined ? { role } : {}),
      ...(phone !== undefined ? { phone } : {}),
    });
    tokensIssued.inc({ grant: 'register' });
    await audit(prisma, {
      actorId: result.user.id, actorEmail: result.user.email, action: 'user.registered',
      targetType: 'user', targetId: result.user.id, metadata: { role: result.user.role }, ip: req.ip,
    });
    return reply.code(201).send(result);
  });

  app.post('/auth/login', async (req) => {
    const body = Credentials.parse(req.body);
    try {
      const result = await login(prisma, body);
      loginAttempts.inc({ result: 'success' });
      tokensIssued.inc({ grant: 'password' });
      await audit(prisma, {
        actorId: result.user.id, actorEmail: result.user.email, action: 'auth.login',
        targetType: 'user', targetId: result.user.id, ip: req.ip,
      });
      return result;
    } catch (err) {
      if (err instanceof AuthError) {
        loginAttempts.inc({ result: 'failure' });
        await audit(prisma, {
          actorEmail: body.email.toLowerCase(), action: 'auth.login_failed',
          metadata: { reason: err.message }, ip: req.ip,
        });
      }
      throw err;
    }
  });

  app.post('/auth/refresh', async (req) => {
    const { refreshToken } = RefreshBody.parse(req.body);
    try {
      const tokens = await refresh(prisma, refreshToken);
      tokensIssued.inc({ grant: 'refresh' });
      return tokens;
    } catch (err) {
      if (err instanceof AuthError && err.message.includes('reuse')) refreshReuseDetected.inc();
      throw err;
    }
  });

  app.post('/auth/logout', async (req, reply) => {
    const { refreshToken } = RefreshBody.parse(req.body);
    await logout(prisma, refreshToken);
    return reply.code(204).send();
  });

  // The gateway verified the JWT and forwards the subject; identity() also
  // checks the internal token, so a direct caller cannot claim to be anyone.
  app.get('/auth/me', async (req, reply) => {
    const { userId } = identity(req);
    const user = await getUser(prisma, userId);
    if (!user) return reply.code(404).send({ error: 'NotFound' });
    return user;
  });

  // Self-service profile. Role and active are deliberately absent: those are
  // an admin's to change, through PATCH /users/:id.
  app.patch('/auth/me', async (req) => {
    const id = identity(req);
    const body = z.object({
      name: z.string().trim().min(1).max(120).optional(),
      phone: Phone.nullable().optional(),
    }).strict().parse(req.body);
    const user = await updateProfile(prisma, id.userId, {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.phone !== undefined ? { phone: body.phone } : {}),
    });
    await audit(prisma, {
      actorId: id.userId, actorEmail: id.email, action: 'user.profile_updated',
      targetType: 'user', targetId: id.userId, metadata: { fields: Object.keys(body) }, ip: req.ip,
    });
    return user;
  });

  app.post('/auth/change-password', async (req, reply) => {
    const id = identity(req);
    const body = z.object({
      currentPassword: z.string().min(1).max(200),
      newPassword: z.string().min(12).max(200),
    }).parse(req.body);
    await changePassword(prisma, id.userId, body);
    await audit(prisma, {
      actorId: id.userId, actorEmail: id.email, action: 'auth.password_changed',
      targetType: 'user', targetId: id.userId, ip: req.ip,
    });
    return reply.code(204).send();
  });
}
