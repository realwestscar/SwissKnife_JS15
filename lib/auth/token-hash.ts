import crypto from 'crypto';
import { env } from '@/lib/config/env';

export function generateOpaqueToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashOpaqueToken(token: string): string {
  return crypto.createHash('sha256').update(`${token}:${env.REFRESH_TOKEN_PEPPER}`).digest('hex');
}
