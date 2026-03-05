import { type NextRequest } from 'next/server';
import { verifyToken, getTokenFromHeader } from '@/lib/auth/jwt';
import { AuthenticationError, AuthorizationError } from '@/lib/utils/errors';
import { type User } from '@/lib/types';

export async function extractUser(request: NextRequest): Promise<User | null> {
  const authHeader = request.headers.get('Authorization');
  const token = getTokenFromHeader(authHeader ?? undefined);

  if (!token) {
    return null;
  }

  const payload = await verifyToken(token);

  if (
    payload.type !== 'access' ||
    typeof payload.sub !== 'string' ||
    typeof payload.email !== 'string' ||
    typeof payload.sid !== 'string'
  ) {
    throw new AuthenticationError('Invalid token payload');
  }

  const issuedAt = typeof payload.iat === 'number' ? new Date(payload.iat * 1000) : new Date();

  return {
    id: payload.sub,
    email: payload.email,
    name: 'User',
    role: (payload.role as User['role']) || 'user',
    status: (payload.status as User['status']) || 'active',
    createdAt: issuedAt,
    updatedAt: issuedAt,
  };
}

export function requireAuth(user: User | null): asserts user is User {
  if (!user) {
    throw new AuthenticationError('Authentication required');
  }
}

export function requireRole(user: User, ...roles: User['role'][]): void {
  if (!roles.includes(user.role)) {
    throw new AuthorizationError(`Insufficient permissions. Required roles: ${roles.join(', ')}`);
  }
}

export function requireActiveStatus(user: User): void {
  if (user.status !== 'active') {
    throw new AuthorizationError(`Account is ${user.status}`);
  }
}
