// Demo accounts for local development: one per role, fixed ids so the other
// services' seed data can reference them. Idempotent - safe to re-run.
//
//   npx tsx --env-file=.env prisma/seed.ts
//
// Never run against a shared database: every account has the same password.
import { PrismaClient, type Role } from '@prisma/client';
import { hashPassword } from '../src/domain/password.js';

export const DEMO_PASSWORD = 'LogiTrack-demo-2026';

const USERS: { id: string; email: string; name: string; role: Role; phone: string }[] = [
  { id: '00000000-0000-4000-8000-000000000001', email: 'admin@logitrack.local', name: 'Amaka Admin', role: 'ADMIN', phone: '+234 801 000 0001' },
  { id: '00000000-0000-4000-8000-000000000002', email: 'dispatch@logitrack.local', name: 'Dayo Dispatcher', role: 'DISPATCHER', phone: '+234 801 000 0002' },
  { id: '00000000-0000-4000-8000-000000000003', email: 'support@logitrack.local', name: 'Sade Support', role: 'SUPPORT', phone: '+234 801 000 0003' },
  { id: '00000000-0000-4000-8000-000000000011', email: 'driver1@logitrack.local', name: 'Tunde Bakare', role: 'DRIVER', phone: '+234 802 111 0011' },
  { id: '00000000-0000-4000-8000-000000000012', email: 'driver2@logitrack.local', name: 'Chidi Okafor', role: 'DRIVER', phone: '+234 802 111 0012' },
  { id: '00000000-0000-4000-8000-000000000013', email: 'driver3@logitrack.local', name: 'Musa Ibrahim', role: 'DRIVER', phone: '+234 802 111 0013' },
  { id: '00000000-0000-4000-8000-000000000021', email: 'customer1@logitrack.local', name: 'Albert Flores', role: 'CUSTOMER', phone: '+234 803 222 0021' },
  { id: '00000000-0000-4000-8000-000000000022', email: 'customer2@logitrack.local', name: 'Kathryn Murphy', role: 'CUSTOMER', phone: '+234 803 222 0022' },
  { id: '00000000-0000-4000-8000-000000000023', email: 'customer3@logitrack.local', name: 'Guy Hawkins', role: 'CUSTOMER', phone: '+234 803 222 0023' },
];

async function main(): Promise<void> {
  const db = new PrismaClient();
  try {
    const passwordHash = await hashPassword(DEMO_PASSWORD);
    for (const u of USERS) {
      await db.user.upsert({
        where: { email: u.email },
        update: { name: u.name, role: u.role, phone: u.phone, active: true },
        create: { ...u, passwordHash },
      });
    }
    console.log(`seeded ${USERS.length} demo users (password: ${DEMO_PASSWORD})`);
    for (const u of USERS) console.log(`  ${u.role.padEnd(10)} ${u.email}`);
  } finally {
    await db.$disconnect();
  }
}

void main();
