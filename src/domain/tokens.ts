import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair, importPKCS8, importSPKI, type CryptoKey, type JWK } from 'jose';

export const ISSUER = 'logitrack-user-service';
export const AUDIENCE = 'logitrack';
const ALG = 'RS256';

// Access tokens are short-lived because nothing can revoke them - the gateway
// verifies signature and expiry offline, with no lookup.
const ACCESS_TTL = '15m';
export const REFRESH_TTL_DAYS = 30;

let privateKey: CryptoKey | null = null;
let publicKey: CryptoKey | null = null;
let kid = '';

/**
 * RS256 rather than HS256 so the gateway holds only the PUBLIC key. With a
 * shared HMAC secret the gateway could mint tokens, so compromising the most
 * exposed service in the platform would mean forging any identity.
 */
export async function initKeys(): Promise<void> {
  const pkcs8 = process.env['JWT_PRIVATE_KEY'];
  const spki = process.env['JWT_PUBLIC_KEY'];

  if (pkcs8 && spki) {
    privateKey = await importPKCS8(pkcs8, ALG);
    publicKey = await importSPKI(spki, ALG);
  } else {
    // Dev convenience only. Every replica generates a different key, so tokens
    // issued by one pod fail verification elsewhere - fine for one local pod,
    // useless in Kubernetes. Production must supply the pair.
    const pair = await generateKeyPair(ALG, { extractable: true });
    privateKey = pair.privateKey;
    publicKey = pair.publicKey;
  }

  const jwk = await exportJWK(publicKey);
  kid = createHash('sha256').update(JSON.stringify([jwk.e, jwk.kty, jwk.n])).digest('base64url').slice(0, 16);
}

export const keysReady = (): boolean => privateKey !== null;

export async function jwks(): Promise<{ keys: JWK[] }> {
  if (!publicKey) throw new Error('keys not initialised');
  const jwk = await exportJWK(publicKey);
  return { keys: [{ ...jwk, kid, alg: ALG, use: 'sig' }] };
}

export interface AccessClaims {
  sub: string;
  email: string;
  role: string;
}

export async function signAccessToken(claims: AccessClaims): Promise<string> {
  if (!privateKey) throw new Error('keys not initialised');
  return new SignJWT({ email: claims.email, role: claims.role })
    .setProtectedHeader({ alg: ALG, kid })
    .setSubject(claims.sub)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(ACCESS_TTL)
    .sign(privateKey);
}

// Refresh tokens are opaque random strings, not JWTs: they must be revocable,
// which means a database lookup, which means there is nothing to gain from
// making them self-describing.
export function newRefreshToken(): { token: string; hash: string } {
  const token = randomBytes(32).toString('base64url');
  return { token, hash: hashRefreshToken(token) };
}

// SHA-256 and not scrypt: the token is 256 bits of entropy, so there is no
// weak password to slow an attacker down over. A fast hash is the right choice.
export const hashRefreshToken = (token: string): string =>
  createHash('sha256').update(token).digest('hex');

export const refreshExpiry = (): Date =>
  new Date(Date.now() + REFRESH_TTL_DAYS * 24 * 60 * 60 * 1000);
