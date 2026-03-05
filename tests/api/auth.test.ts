import { beforeEach, describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { resetMockDatabase } from '@/lib/db/client';
import { resetRateLimitStore } from '@/lib/middleware/rate-limit';

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
});
