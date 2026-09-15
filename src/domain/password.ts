import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (p: string, s: Buffer, k: number, o: object) => Promise<Buffer>;

// OWASP-recommended scrypt parameters. N is the work factor; raising it makes
// offline cracking proportionally more expensive.
const N = 2 ** 16;
const r = 8;
const p = 1;
const KEYLEN = 64;
// scrypt needs roughly 128 * N * r bytes; the default 32 MB cap rejects N=65536.
const MAXMEM = 256 * 1024 * 1024;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, KEYLEN, { N, r, p, maxmem: MAXMEM });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const [, sN, sr, sp, saltB64, keyB64] = parts;
  const salt = Buffer.from(saltB64!, 'base64');
  const expected = Buffer.from(keyB64!, 'base64');

  const actual = await scrypt(password, salt, expected.length, {
    N: Number(sN), r: Number(sr), p: Number(sp), maxmem: MAXMEM,
  });
  // Constant time: a length-sensitive or short-circuiting compare leaks the
  // hash one byte at a time.
  if (actual.length !== expected.length) return false;
  return timingSafeEqual(actual, expected);
}
