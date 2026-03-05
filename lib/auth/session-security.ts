import crypto from 'crypto';
import { env } from '@/lib/config/env';

export function generateTokenId() {
  return crypto.randomUUID();
}

export function hashRefreshToken(token: string): string {
  return crypto.createHash('sha256').update(`${token}${env.REFRESH_TOKEN_PEPPER}`).digest('hex');
}

export function safeEqualHash(expected: string, actual: string): boolean {
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);

  if (expectedBuffer.length !== actualBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}
