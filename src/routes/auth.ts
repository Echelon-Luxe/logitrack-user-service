import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../db/client.js';
import { register, login, refresh, logout, getUser, AuthError } from '../domain/auth.js';
import { jwks } from '../domain/tokens.js';
import { loginAttempts, tokensIssued, refreshReuseDetected } from '../metrics.js';

const Credentials = z.object({
  email: z.string().email().max(254),
  // Length is the dominant factor in password strength; a composition rule
  // mostly teaches people to write Passw0rd!.
  password: z.string().min(12).max(200),
});

const RefreshBody = z.object({ refreshToken: z.string().min(1) });

export async function authRoutes(app: FastifyInstance): Promise<void> {
  // The gateway fetches this to verify tokens. Only the PUBLIC key is here.
  app.get('/.well-known/jwks.json', async (_req, reply) => {
    reply.header('cache-control', 'public, max-age=300');
    return jwks();
  });

  app.post('/auth/register', async (req, reply) => {
    const body = Credentials.extend({
      name: z.string().min(1).max(120),
      // Self-service registration cannot grant ADMIN; that would be privilege
      // escalation by request body.
      role: z.enum(['CUSTOMER', 'DRIVER']).optional(),
    }).parse(req.body);

    // exactOptionalPropertyTypes: an explicit undefined is not an omitted key.
    const { role, ...rest } = body;
    const result = await register(prisma, { ...rest, ...(role !== undefined ? { role } : {}) });
    tokensIssued.inc({ grant: 'register' });
    return reply.code(201).send(result);
  });

  app.post('/auth/login', async (req) => {
    const body = Credentials.parse(req.body);
    try {
      const result = await login(prisma, body);
      loginAttempts.inc({ result: 'success' });
      tokensIssued.inc({ grant: 'password' });
      return result;
    } catch (err) {
      if (err instanceof AuthError) loginAttempts.inc({ result: 'failure' });
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

  // The gateway has already verified the JWT and forwards the subject. Safe
  // only because backends are ClusterIP-only and unreachable from outside.
  app.get('/auth/me', async (req, reply) => {
    const userId = req.headers['x-user-id'];
    if (typeof userId !== 'string') return reply.code(401).send({ error: 'Unauthorized' });
    const user = await getUser(prisma, userId);
    if (!user) return reply.code(404).send({ error: 'NotFound' });
    return user;
  });

  app.get('/users/:id', async (req, reply) => {
    const { id } = z.object({ id: z.string().uuid() }).parse(req.params);
    const user = await getUser(prisma, id);
    if (!user) return reply.code(404).send({ error: 'NotFound' });
    return user;
  });
}
