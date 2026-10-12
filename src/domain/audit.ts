import type { PrismaClient, Prisma } from '@prisma/client';

export interface AuditEntry {
  actorId?: string | null;
  actorEmail?: string | null;
  action: string;
  targetType?: string;
  targetId?: string;
  metadata?: Record<string, unknown>;
  ip?: string;
}

/**
 * Best-effort: an audit write failing must not fail the action it describes,
 * or a full audit table would lock everyone out of logging in. The failure is
 * logged by the caller's error path instead.
 */
export async function audit(db: Pick<PrismaClient, 'auditLog'>, e: AuditEntry): Promise<void> {
  try {
    await db.auditLog.create({
      data: {
        actorId: e.actorId ?? null,
        actorEmail: e.actorEmail ?? null,
        action: e.action,
        targetType: e.targetType ?? null,
        targetId: e.targetId ?? null,
        ...(e.metadata ? { metadata: e.metadata as Prisma.InputJsonValue } : {}),
        ip: e.ip ?? null,
      },
    });
  } catch {
    /* see above */
  }
}

export async function listAudit(
  db: PrismaClient,
  filter: { action?: string; actorId?: string; targetId?: string; q?: string; cursor?: string; limit?: number },
) {
  const take = Math.min(filter.limit ?? 50, 200);
  const rows = await db.auditLog.findMany({
    where: {
      ...(filter.action ? { action: { startsWith: filter.action } } : {}),
      ...(filter.actorId ? { actorId: filter.actorId } : {}),
      ...(filter.targetId ? { targetId: filter.targetId } : {}),
      ...(filter.q
        ? {
            OR: [
              { actorEmail: { contains: filter.q, mode: 'insensitive' as const } },
              { action: { contains: filter.q, mode: 'insensitive' as const } },
            ],
          }
        : {}),
    },
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: take + 1,
    ...(filter.cursor ? { cursor: { id: filter.cursor }, skip: 1 } : {}),
  });
  const more = rows.length > take;
  const items = more ? rows.slice(0, take) : rows;
  return { items, nextCursor: more ? items[items.length - 1]!.id : null };
}
