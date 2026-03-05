import { beforeEach, describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { db, resetMockDatabase } from '@/lib/db/client';
import { signToken } from '@/lib/auth/jwt';
import { resetRateLimitStore } from '@/lib/middleware/rate-limit';
import crypto from 'crypto';

function createJsonRequest(url: string, method: 'GET' | 'POST' | 'PATCH', body?: Record<string, unknown>, token?: string) {
  return new NextRequest(url, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function createNonJsonPatchRequest(url: string, body: string, token: string) {
  return new NextRequest(url, {
    method: 'PATCH',
    headers: {
      'content-type': 'text/plain',
      Authorization: `Bearer ${token}`,
    },
    body,
  });
}

async function registerUser(email: string, name: string, password: string) {
  const { POST: registerPost } = await import('@/app/api/auth/register/route');
  const response = await registerPost(
    createJsonRequest('http://localhost/api/auth/register', 'POST', {
      email,
      name,
      password,
    })
  );
  const payload = await response.json();
  return payload.data.user as { id: string; email: string; name: string; role: 'user' | 'admin' };
}

async function createAccessToken(userId: string) {
  const user = await db.findUserById(userId);
  if (!user) {
    throw new Error('Expected test user to exist');
  }

  return signToken({
    sub: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    status: user.status,
    sid: crypto.randomUUID(),
    type: 'access',
  });
}

describe('Users API', () => {
  beforeEach(async () => {
    await resetMockDatabase();
    await resetRateLimitStore();
  });

  it('requires auth for listing users', async () => {
    const { GET: listUsers } = await import('@/app/api/users/route');

    const response = await listUsers(createJsonRequest('http://localhost/api/users', 'GET'));
    const payload = await response.json();

    expect(response.status).toBe(401);
    expect(payload.error.code).toBe('AUTHENTICATION_ERROR');
  });

  it('forbids non-admin users from listing users', async () => {
    const normalUser = await registerUser('list-user@example.com', 'List User', 'StrongPassword123!');
    const token = await createAccessToken(normalUser.id);
    const { GET: listUsers } = await import('@/app/api/users/route');

    const response = await listUsers(createJsonRequest('http://localhost/api/users', 'GET', undefined, token));
    const payload = await response.json();

    expect(response.status).toBe(403);
    expect(payload.error.code).toBe('AUTHORIZATION_ERROR');
  });

  it('allows admin users to list users with pagination metadata', async () => {
    const admin = await registerUser('admin-list@example.com', 'Admin User', 'StrongPassword123!');
    const member = await registerUser('member-list@example.com', 'Member User', 'StrongPassword123!');
    await db.updateUser(admin.id, { role: 'admin' });
    const token = await createAccessToken(admin.id);
    const { GET: listUsers } = await import('@/app/api/users/route');

    const response = await listUsers(createJsonRequest('http://localhost/api/users?page=1&limit=10', 'GET', undefined, token));
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get('x-request-id')).toBeTruthy();
    expect(payload.meta.pagination.page).toBe(1);
    expect(payload.meta.pagination.limit).toBe(10);
    expect(payload.data.some((u: { id: string }) => u.id === member.id)).toBe(true);
  });

  it('rejects non-json PATCH payloads', async () => {
    const user = await registerUser('json-check@example.com', 'Json Check', 'StrongPassword123!');
    const token = await createAccessToken(user.id);
    const { PATCH: patchUser } = await import('@/app/api/users/[id]/route');

    const response = await patchUser(
      createNonJsonPatchRequest(`http://localhost/api/users/${user.id}`, 'name=test', token),
      { params: Promise.resolve({ id: user.id }) }
    );
    const payload = await response.json();

    expect(response.status).toBe(400);
    expect(payload.error.code).toBe('VALIDATION_ERROR');
  });

  it('validates payload before role authorization checks', async () => {
    const user = await registerUser('validation-order@example.com', 'Validation Order', 'StrongPassword123!');
    const token = await createAccessToken(user.id);
    const { PATCH: patchUser } = await import('@/app/api/users/[id]/route');

    const response = await patchUser(
      createJsonRequest(`http://localhost/api/users/${user.id}`, 'PATCH', { role: 'superadmin' }, token),
      { params: Promise.resolve({ id: user.id }) }
    );
    const payload = await response.json();

    expect(response.status).toBe(400);
    expect(payload.error.code).toBe('VALIDATION_ERROR');
  });

  it('prevents non-admin role escalation while allowing admin role updates', async () => {
    const admin = await registerUser('admin-patch@example.com', 'Admin Patch', 'StrongPassword123!');
    const member = await registerUser('member-patch@example.com', 'Member Patch', 'StrongPassword123!');
    await db.updateUser(admin.id, { role: 'admin' });

    const memberToken = await createAccessToken(member.id);
    const adminToken = await createAccessToken(admin.id);
    const { PATCH: patchUser } = await import('@/app/api/users/[id]/route');

    const nonAdminAttempt = await patchUser(
      createJsonRequest(`http://localhost/api/users/${member.id}`, 'PATCH', { role: 'admin' }, memberToken),
      { params: Promise.resolve({ id: member.id }) }
    );
    const nonAdminPayload = await nonAdminAttempt.json();

    expect(nonAdminAttempt.status).toBe(403);
    expect(nonAdminPayload.error.code).toBe('AUTHORIZATION_ERROR');

    const adminAttempt = await patchUser(
      createJsonRequest(`http://localhost/api/users/${member.id}`, 'PATCH', { role: 'admin' }, adminToken),
      { params: Promise.resolve({ id: member.id }) }
    );
    const adminPayload = await adminAttempt.json();

    expect(adminAttempt.status).toBe(200);
    expect(adminPayload.data.role).toBe('admin');
  });
});
