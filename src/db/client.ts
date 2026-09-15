import { PrismaClient } from '@prisma/client';

// One client per process: each opens its own pool against Supabase.
export const prisma = new PrismaClient({
  log: process.env['LOG_LEVEL'] === 'debug' ? ['warn', 'error'] : ['error'],
});

export async function pingDb(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}
