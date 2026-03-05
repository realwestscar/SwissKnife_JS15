import { SignJWT, jwtVerify } from 'jose';
import { env } from '@/lib/config/env';
import { AuthenticationError } from '@/lib/utils/errors';

function getJwtSecret() {
  return new TextEncoder().encode(env.JWT_SECRET);
}

export async function signToken(payload: Record<string, unknown>, expiresIn: string = env.JWT_EXPIRY) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(getJwtSecret());
}

export async function verifyToken(token: string) {
  try {
    const verified = await jwtVerify(token, getJwtSecret());
    return verified.payload;
  } catch {
    throw new AuthenticationError('Invalid or expired token');
  }
}

export function getTokenFromHeader(header: string | undefined): string | null {
  if (!header) return null;
  const match = header.match(/Bearer\s+(.+)/i);
  return match ? match[1] : null;
}
