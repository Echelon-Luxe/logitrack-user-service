import { describe, it, expect, beforeAll } from 'vitest';
import { jwtVerify, createLocalJWKSet, decodeProtectedHeader } from 'jose';
import { initKeys, jwks, signAccessToken, newRefreshToken, hashRefreshToken, ISSUER, AUDIENCE } from '../src/domain/tokens.js';

beforeAll(async () => { await initKeys(); });

describe('access tokens', () => {
  it('verifies against the published JWKS', async () => {
    const token = await signAccessToken({ sub: 'u1', email: 'a@b.c', role: 'CUSTOMER' });
    const keySet = createLocalJWKSet(await jwks());
    const { payload } = await jwtVerify(token, keySet, { issuer: ISSUER, audience: AUDIENCE });
    expect(payload.sub).toBe('u1');
    expect(payload['role']).toBe('CUSTOMER');
  });

  it('signs with RS256 and carries a kid', async () => {
    const header = decodeProtectedHeader(await signAccessToken({ sub: 'u1', email: 'a@b.c', role: 'ADMIN' }));
    expect(header.alg).toBe('RS256');
    expect(header.kid).toBeTruthy();
  });

  // The whole reason for RS256: the gateway gets a verify-only key.
  it('publishes only the public half', async () => {
    const set = await jwks();
    const k = set.keys[0] as Record<string, unknown>;
    expect(k['kty']).toBe('RSA');
    expect(k['n']).toBeTruthy();
    // Private RSA parameters must never appear.
    for (const priv of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(k[priv]).toBeUndefined();
  });

  it('rejects a token with the wrong audience', async () => {
    const token = await signAccessToken({ sub: 'u1', email: 'a@b.c', role: 'CUSTOMER' });
    const keySet = createLocalJWKSet(await jwks());
    await expect(jwtVerify(token, keySet, { issuer: ISSUER, audience: 'someone-else' }))
      .rejects.toThrow();
  });

  it('rejects a tampered payload', async () => {
    const token = await signAccessToken({ sub: 'u1', email: 'a@b.c', role: 'CUSTOMER' });
    const [h, p, s] = token.split('.');
    const forged = JSON.parse(Buffer.from(p!, 'base64url').toString());
    forged.role = 'ADMIN';
    const tampered = `${h}.${Buffer.from(JSON.stringify(forged)).toString('base64url')}.${s}`;
    const keySet = createLocalJWKSet(await jwks());
    await expect(jwtVerify(tampered, keySet, { issuer: ISSUER, audience: AUDIENCE }))
      .rejects.toThrow();
  });

  it('sets an expiry', async () => {
    const token = await signAccessToken({ sub: 'u1', email: 'a@b.c', role: 'CUSTOMER' });
    const keySet = createLocalJWKSet(await jwks());
    const { payload } = await jwtVerify(token, keySet, { issuer: ISSUER, audience: AUDIENCE });
    expect(payload.exp).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(payload.exp! - payload.iat!).toBe(900);
  });
});

describe('refresh tokens', () => {
  it('generates high-entropy opaque tokens', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) seen.add(newRefreshToken().token);
    expect(seen.size).toBe(200);
    expect([...seen][0]!.length).toBeGreaterThanOrEqual(42);
  });

  it('stores only a hash', () => {
    const { token, hash } = newRefreshToken();
    expect(hash).not.toBe(token);
    expect(hash).toHaveLength(64);
    expect(hashRefreshToken(token)).toBe(hash);
  });

  it('is not a JWT', () => {
    // Opaque by design: revocation needs a lookup, so self-describing buys nothing.
    expect(newRefreshToken().token.split('.')).toHaveLength(1);
  });
});
