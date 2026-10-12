import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { prisma } from '../db/client.js';
import { getUser, revokeAllSessions } from '../domain/auth.js';
import { listUsers, userSummary, createUser, updateUser, resetPassword, NotFoundError } from '../domain/users.js';
import { audit, listAudit } from '../domain/audit.js';
import { identity, requireRole, STAFF, ROLES } from '../authz.js';
import { Phone } from './auth.js';

const IdParam = z.object({ id: z.string().uuid() });

// The gateway already limits /users reads to staff and writes to ADMIN. These
// checks repeat that, so the rule holds even if the route table is edited.
export async function userRoutes(app: FastifyInstance): Promise<void> {
  app.get('/users', async (req) => {
    requireRole(identity(req), STAFF);
    const q = z.object({
      q: z.string().trim().max(120).optional(),
      role: z.enum(ROLES).optional(),
      active: z.enum(['true', 'false']).transform((v) => v === 'true').optional(),
      cursor: z.string().uuid().optional(),
      limit: z.coerce.number().int().positive().max(200).optional(),
    }).parse(req.query);
    return listUsers(prisma, {
      ...(q.q ? { q: q.q } : {}),
      ...(q.role ? { role: q.role } : {}),
      ...(q.active !== undefined ? { active: q.active } : {}),
      ...(q.cursor ? { cursor: q.cursor } : {}),
      ...(q.limit ? { limit: q.limit } : {}),
    });
  });

  app.get('/users/summary', async (req) => {
    requireRole(identity(req), STAFF);
    return userSummary(prisma);
  });

  app.get('/users/:id', async (req) => {
    requireRole(identity(req), STAFF);
    const { id } = IdParam.parse(req.params);
    const user = await getUser(prisma, id);
    if (!user) throw new NotFoundError(id);
    return user;
  });

  app.post('/users', async (req, reply) => {
    const actor = identity(req);
    requireRole(actor, ['ADMIN']);
    const body = z.object({
      email: z.string().email().max(254),
      name: z.string().trim().min(1).max(120),
      role: z.enum(ROLES),
      phone: Phone.optional(),
      password: z.string().min(12).max(200).optional(),
    }).parse(req.body);
    const { phone, password, ...rest } = body;
    const result = await createUser(prisma, {
      ...rest,
      ...(phone !== undefined ? { phone } : {}),
      ...(password !== undefined ? { password } : {}),
    });
    await audit(prisma, {
      actorId: actor.userId, actorEmail: actor.email, action: 'user.created',
      targetType: 'user', targetId: result.user.id,
      metadata: { email: result.user.email, role: result.user.role }, ip: req.ip,
    });
    return reply.code(201).send(result);
  });

  app.patch('/users/:id', async (req) => {
    const actor = identity(req);
    requireRole(actor, ['ADMIN']);
    const { id } = IdParam.parse(req.params);
    const body = z.object({
      name: z.string().trim().min(1).max(120).optional(),
      phone: Phone.nullable().optional(),
      role: z.enum(ROLES).optional(),
      active: z.boolean().optional(),
    }).strict().parse(req.body);

    const { user, before, sessionsRevoked } = await updateUser(prisma, actor.userId, id, {
      ...(body.name !== undefined ? { name: body.name } : {}),
      ...(body.phone !== undefined ? { phone: body.phone } : {}),
      ...(body.role !== undefined ? { role: body.role } : {}),
      ...(body.active !== undefined ? { active: body.active } : {}),
    });

    // One row per meaningful change, so the log reads as a story.
    const base = { actorId: actor.userId, actorEmail: actor.email, targetType: 'user', targetId: id, ip: req.ip };
    if (body.role !== undefined && body.role !== before.role) {
      await audit(prisma, { ...base, action: 'user.role_changed', metadata: { from: before.role, to: body.role, email: user.email } });
    }
    if (body.active !== undefined && body.active !== before.active) {
      await audit(prisma, { ...base, action: body.active ? 'user.enabled' : 'user.disabled', metadata: { email: user.email } });
    }
    if (body.name !== undefined || body.phone !== undefined) {
      await audit(prisma, { ...base, action: 'user.updated', metadata: { email: user.email, fields: Object.keys(body).filter((k) => k === 'name' || k === 'phone') } });
    }
    return { ...user, sessionsRevoked };
  });

  app.post('/users/:id/revoke-sessions', async (req) => {
    const actor = identity(req);
    requireRole(actor, ['ADMIN']);
    const { id } = IdParam.parse(req.params);
    const user = await getUser(prisma, id);
    if (!user) throw new NotFoundError(id);
    const revoked = await revokeAllSessions(prisma, id);
    await audit(prisma, {
      actorId: actor.userId, actorEmail: actor.email, action: 'user.sessions_revoked',
      targetType: 'user', targetId: id, metadata: { email: user.email, revoked }, ip: req.ip,
    });
    return { revoked };
  });

  app.post('/users/:id/reset-password', async (req) => {
    const actor = identity(req);
    requireRole(actor, ['ADMIN']);
    const { id } = IdParam.parse(req.params);
    const r = await resetPassword(prisma, id);
    await audit(prisma, {
      actorId: actor.userId, actorEmail: actor.email, action: 'user.password_reset',
      targetType: 'user', targetId: id, metadata: { email: r.email }, ip: req.ip,
    });
    return { temporaryPassword: r.temporaryPassword };
  });

  app.get('/audit', async (req) => {
    requireRole(identity(req), ['ADMIN']);
    const q = z.object({
      action: z.string().max(60).optional(),
      actorId: z.string().optional(),
      targetId: z.string().optional(),
      q: z.string().trim().max(120).optional(),
      cursor: z.string().uuid().optional(),
      limit: z.coerce.number().int().positive().max(200).optional(),
    }).parse(req.query);
    return listAudit(prisma, {
      ...(q.action ? { action: q.action } : {}),
      ...(q.actorId ? { actorId: q.actorId } : {}),
      ...(q.targetId ? { targetId: q.targetId } : {}),
      ...(q.q ? { q: q.q } : {}),
      ...(q.cursor ? { cursor: q.cursor } : {}),
      ...(q.limit ? { limit: q.limit } : {}),
    });
  });
}
