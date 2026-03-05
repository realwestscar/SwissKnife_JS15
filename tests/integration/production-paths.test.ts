import { beforeEach, describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { db, resetMockDatabase } from '@/lib/db/client';

const describeIfDatabase = process.env.DATABASE_URL ? describe : describe.skip;

describeIfDatabase('Integration - production data paths', () => {
  beforeEach(async () => {
    await resetMockDatabase();
  });

  it('writes users to postgres-backed repository', async () => {
    const { POST: registerPost } = await import('@/app/api/auth/register/route');
    const registerResponse = await registerPost(
      new NextRequest('http://localhost/api/auth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: 'integration-user@example.com',
          name: 'Integration User',
          password: 'StrongPassword123!',
        }),
      })
    );

    expect(registerResponse.status).toBe(201);

    const user = await db.findUserByEmail('integration-user@example.com');
    expect(user).toBeTruthy();
    expect(user?.email).toBe('integration-user@example.com');
  });

  it('readiness endpoint reports healthy dependencies', async () => {
    const { GET } = await import('@/app/api/health/ready/route');
    const response = await GET();
    expect(response.status).toBe(200);
  });
});
