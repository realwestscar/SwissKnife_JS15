import crypto from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { SignJWT } from 'jose';
import { db, resetMockDatabase } from '@/lib/db/client';
import { resetRateLimitStore } from '@/lib/middleware/rate-limit';
import { signToken } from '@/lib/auth/jwt';

function createAuthRequest(url: string, method: 'GET' | 'POST', token?: string, body?: Record<string, unknown>) {
  return new NextRequest(url, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function createJsonRequest(url: string, body: Record<string, unknown>) {
  return new NextRequest(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('Auth API', () => {
  beforeEach(async () => {
    await resetMockDatabase();
    await resetRateLimitStore();
  });

  it('rejects refresh tokens passed to extractUser-protected routes with 401', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'refresh-as-access@example.com',
        name: 'Refresh As Access',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();
    const { GET: listUsers } = await import('@/app/api/users/route');

    const response = await listUsers(createAuthRequest('http://localhost/api/users', 'GET', registerPayload.data.refresh_token));
    expect(response.status).toBe(401);
  });

  it('returns 401 (not 500) for expired access token', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'expired-access@example.com',
        name: 'Expired Access',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();
    await db.updateUser(registerPayload.data.user.id, { role: 'admin' });

    const expiredToken = await new SignJWT({
      sub: registerPayload.data.user.id,
      email: 'expired-access@example.com',
      name: 'Expired Access',
      role: 'admin',
      status: 'active',
      type: 'access',
      sid: crypto.randomUUID(),
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt(1)
      .setExpirationTime(2)
      .sign(new TextEncoder().encode(process.env.JWT_SECRET ?? 'test-jwt-secret-12345678901234567890'));

    const { GET: listUsers } = await import('@/app/api/users/route');
    const response = await listUsers(createAuthRequest('http://localhost/api/users', 'GET', expiredToken));

    expect(response.status).toBe(401);
  });

  it('returns 401 for tampered JWT signatures', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'tampered-jwt@example.com',
        name: 'Tampered JWT',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();
    await db.updateUser(registerPayload.data.user.id, { role: 'admin' });

    const validToken = await signToken({
      sub: registerPayload.data.user.id,
      email: 'tampered-jwt@example.com',
      name: 'Tampered JWT',
      role: 'admin',
      status: 'active',
      type: 'access',
      sid: crypto.randomUUID(),
    });
    const parts = validToken.split('.');
    parts[2] = `${parts[2]}tampered`;
    const tamperedToken = parts.join('.');

    const { GET: listUsers } = await import('@/app/api/users/route');
    const response = await listUsers(createAuthRequest('http://localhost/api/users', 'GET', tamperedToken));

    expect(response.status).toBe(401);
  });

  it('register ignores client role escalation attempts', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');

    const response = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'role-test@example.com',
        name: 'Role Test',
        password: 'StrongPassword123!',
        role: 'admin',
      })
    );

    const payload = await response.json();

    expect(response.status).toBe(201);
    expect(response.headers.get('x-request-id')).toBeTruthy();
    expect(payload.success).toBe(true);
    expect(payload.data.user.role).toBe('user');
    expect(typeof payload.data.access_token).toBe('string');
    expect(typeof payload.data.refresh_token).toBe('string');
    expect(typeof payload.data.session_id).toBe('string');
  });

  it('login rejects unknown users with a generic auth error', async () => {
    const { POST: loginPost } = await import('@/app/api/auth/login/route');

    const response = await loginPost(
      createJsonRequest('http://localhost/api/auth/login', {
        email: 'unknown@example.com',
        password: 'WrongPassword123!',
      })
    );

    const payload = await response.json();

    expect(response.status).toBe(401);
    expect(payload.success).toBe(false);
    expect(payload.error.message).toBe('Invalid email or password');
  });

  it('refresh endpoint requires a refresh token type', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'refresh-test@example.com',
        name: 'Refresh Test',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();

    const { POST: refreshPost } = await import('@/app/api/auth/refresh/route');

    const badRefresh = await refreshPost(
      new NextRequest('http://localhost/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: `Bearer ${registerPayload.data.access_token}` },
      })
    );
    expect(badRefresh.status).toBe(401);

    const validRefresh = await refreshPost(
      new NextRequest('http://localhost/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: `Bearer ${registerPayload.data.refresh_token}` },
      })
    );
    const refreshPayload = await validRefresh.json();

    expect(validRefresh.status).toBe(200);
    expect(refreshPayload.success).toBe(true);
    expect(typeof refreshPayload.data.access_token).toBe('string');
    expect(typeof refreshPayload.data.refresh_token).toBe('string');
    expect(refreshPayload.data.refresh_token).not.toBe(registerPayload.data.refresh_token);
  });

  it('detects refresh token reuse after rotation', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'reuse-test@example.com',
        name: 'Reuse Test',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();

    const { POST: refreshPost } = await import('@/app/api/auth/refresh/route');
    const firstRefresh = await refreshPost(
      new NextRequest('http://localhost/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: `Bearer ${registerPayload.data.refresh_token}` },
      })
    );
    const firstRefreshPayload = await firstRefresh.json();
    expect(firstRefresh.status).toBe(200);

    const replayedRefresh = await refreshPost(
      new NextRequest('http://localhost/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: `Bearer ${registerPayload.data.refresh_token}` },
      })
    );
    expect(replayedRefresh.status).toBe(401);

    const familyRevokedRefresh = await refreshPost(
      new NextRequest('http://localhost/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: `Bearer ${firstRefreshPayload.data.refresh_token}` },
      })
    );
    expect(familyRevokedRefresh.status).toBe(401);
  });

  it('logout revokes refresh session', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'logout-test@example.com',
        name: 'Logout Test',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();

    const { POST: logoutPost } = await import('@/app/api/auth/logout/route');
    const logoutResponse = await logoutPost(
      new NextRequest('http://localhost/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${registerPayload.data.refresh_token}` },
      })
    );
    expect(logoutResponse.status).toBe(200);

    const { POST: refreshPost } = await import('@/app/api/auth/refresh/route');
    const refreshAfterLogout = await refreshPost(
      new NextRequest('http://localhost/api/auth/refresh', {
        method: 'POST',
        headers: { Authorization: `Bearer ${registerPayload.data.refresh_token}` },
      })
    );
    expect(refreshAfterLogout.status).toBe(401);
  });

  it('returns 429 on the 6th login attempt from the same email within 15 minutes', async () => {
    const { POST: loginPost } = await import('@/app/api/auth/login/route');

    for (let i = 0; i < 5; i++) {
      const response = await loginPost(
        createJsonRequest('http://localhost/api/auth/login', {
          email: 'rate-limit-login@example.com',
          password: 'WrongPassword123!',
        })
      );
      expect(response.status).toBe(401);
    }

    const sixthResponse = await loginPost(
      createJsonRequest('http://localhost/api/auth/login', {
        email: 'rate-limit-login@example.com',
        password: 'WrongPassword123!',
      })
    );

    expect(sixthResponse.status).toBe(429);
  });

  it('returns 429 on the 6th register attempt from the same IP within 1 hour', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');

    for (let i = 0; i < 5; i++) {
      const response = await registerPost(
        createJsonRequest('http://localhost/api/auth/register', {
          email: `register-limit-${i}@example.com`,
          name: `Register Limit ${i}`,
          password: 'StrongPassword123!',
        })
      );
      expect(response.status).toBe(201);
    }

    const sixthResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'register-limit-5@example.com',
        name: 'Register Limit 5',
        password: 'StrongPassword123!',
      })
    );

    expect(sixthResponse.status).toBe(429);
  });

  it('supports full flow register -> login -> refresh -> logout -> refresh fails', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'full-flow@example.com',
        name: 'Full Flow',
        password: 'StrongPassword123!',
      })
    );
    expect(registerResponse.status).toBe(201);

    const { POST: loginPost } = await import('@/app/api/auth/login/route');
    const loginResponse = await loginPost(
      createJsonRequest('http://localhost/api/auth/login', {
        email: 'full-flow@example.com',
        password: 'StrongPassword123!',
      })
    );
    const loginPayload = await loginResponse.json();
    expect(loginResponse.status).toBe(200);

    const { POST: refreshPost } = await import('@/app/api/auth/refresh/route');
    const refreshResponse = await refreshPost(createAuthRequest('http://localhost/api/auth/refresh', 'POST', loginPayload.data.refresh_token));
    const refreshPayload = await refreshResponse.json();
    expect(refreshResponse.status).toBe(200);

    const { POST: logoutPost } = await import('@/app/api/auth/logout/route');
    const logoutResponse = await logoutPost(createAuthRequest('http://localhost/api/auth/logout', 'POST', refreshPayload.data.refresh_token));
    expect(logoutResponse.status).toBe(200);

    const failedRefresh = await refreshPost(createAuthRequest('http://localhost/api/auth/refresh', 'POST', refreshPayload.data.refresh_token));
    expect(failedRefresh.status).toBe(401);
  });

  it('invalidates token family when the same refresh token is replayed concurrently', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      createJsonRequest('http://localhost/api/auth/register', {
        email: 'concurrent-refresh@example.com',
        name: 'Concurrent Refresh',
        password: 'StrongPassword123!',
      })
    );
    const registerPayload = await registerResponse.json();

    const { POST: refreshPost } = await import('@/app/api/auth/refresh/route');
    const firstRefresh = await refreshPost(createAuthRequest('http://localhost/api/auth/refresh', 'POST', registerPayload.data.refresh_token));
    const firstPayload = await firstRefresh.json();
    expect(firstRefresh.status).toBe(200);

    const [replayA, replayB] = await Promise.all([
      refreshPost(createAuthRequest('http://localhost/api/auth/refresh', 'POST', registerPayload.data.refresh_token)),
      refreshPost(createAuthRequest('http://localhost/api/auth/refresh', 'POST', registerPayload.data.refresh_token)),
    ]);

    expect(replayA.status).toBe(401);
    expect(replayB.status).toBe(401);

    const familyRevoked = await refreshPost(createAuthRequest('http://localhost/api/auth/refresh', 'POST', firstPayload.data.refresh_token));
    expect(familyRevoked.status).toBe(401);
  });

  it('allows requests when failOpen=true and Redis is unavailable', async () => {
    const originalEnv = { ...process.env };
    process.env.UPSTASH_REDIS_REST_URL = 'https://example.com';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'token';
    process.env.ALLOW_IN_MEMORY_RATE_LIMIT = 'false';
    process.env.ALLOW_IN_MEMORY_SERVICES = 'false';
    process.env.ALLOW_IN_MEMORY_DB = 'true';
    process.env.RATE_LIMIT_ENABLED = 'true';

    vi.resetModules();
    vi.doMock('@/lib/platform/redis', () => ({
      getRedisClient: () => {
        throw new Error('Redis unavailable');
      },
    }));

    const { checkRateLimit } = await import('@/lib/middleware/rate-limit');
    await expect(checkRateLimit('fail-open:test', { failOpen: true })).resolves.toBeUndefined();

    vi.doUnmock('@/lib/platform/redis');
    Object.assign(process.env, originalEnv);
  });

  it('returns 503 when failOpen=false and Redis is unavailable', async () => {
    const originalEnv = { ...process.env };
    process.env.UPSTASH_REDIS_REST_URL = 'https://example.com';
    process.env.UPSTASH_REDIS_REST_TOKEN = 'token';
    process.env.ALLOW_IN_MEMORY_RATE_LIMIT = 'false';
    process.env.ALLOW_IN_MEMORY_SERVICES = 'false';
    process.env.ALLOW_IN_MEMORY_DB = 'true';
    process.env.RATE_LIMIT_ENABLED = 'true';

    vi.resetModules();
    vi.doMock('@/lib/platform/redis', () => ({
      getRedisClient: () => {
        throw new Error('Redis unavailable');
      },
    }));

    const { checkRateLimit } = await import('@/lib/middleware/rate-limit');
    await expect(checkRateLimit('fail-closed:test', { failOpen: false })).rejects.toMatchObject({
      code: 'SERVICE_UNAVAILABLE',
      status: 503,
    });

    vi.doUnmock('@/lib/platform/redis');
    Object.assign(process.env, originalEnv);
  });
});
