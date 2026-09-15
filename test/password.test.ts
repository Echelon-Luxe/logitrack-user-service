import { describe, it, expect } from 'vitest';
import { hashPassword, verifyPassword } from '../src/domain/password.js';

describe('password hashing', () => {
  it('verifies a correct password', async () => {
    const h = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('correct horse battery staple', h)).toBe(true);
  });

  it('rejects a wrong password', async () => {
    const h = await hashPassword('correct horse battery staple');
    expect(await verifyPassword('Correct horse battery staple', h)).toBe(false);
  });

  // Distinct salts mean identical passwords do not produce identical hashes,
  // so a database leak cannot be attacked with one precomputed table.
  it('produces a different hash each time', async () => {
    const a = await hashPassword('same password');
    const b = await hashPassword('same password');
    expect(a).not.toBe(b);
    expect(await verifyPassword('same password', a)).toBe(true);
    expect(await verifyPassword('same password', b)).toBe(true);
  });

  it('never stores the password in the hash string', async () => {
    const h = await hashPassword('supersecretvalue');
    expect(h).not.toContain('supersecretvalue');
  });

  it('records its parameters so they can be raised later', async () => {
    const h = await hashPassword('x'.repeat(12));
    expect(h.startsWith('scrypt$65536$8$1$')).toBe(true);
    expect(h.split('$')).toHaveLength(6);
  });

  it('rejects a malformed stored hash instead of throwing', async () => {
    for (const bad of ['', 'not-a-hash', 'scrypt$1$2', 'bcrypt$1$2$3$4$5']) {
      await expect(verifyPassword('x', bad)).resolves.toBe(false);
    }
  });

  it('handles unicode and long passwords', async () => {
    const pw = 'пароль-密码-🔐-' + 'a'.repeat(150);
    expect(await verifyPassword(pw, await hashPassword(pw))).toBe(true);
  });
});
