This file is a merged representation of a subset of the codebase, containing specifically included files, combined into a single document by Repomix.

# File Summary

## Purpose
This file contains a packed representation of a subset of the repository's contents that is considered the most important context.
It is designed to be easily consumable by AI systems for analysis, code review,
or other automated processes.

## File Format
The content is organized as follows:
1. This summary section
2. Repository information
3. Directory structure
4. Repository files (if enabled)
5. Multiple file entries, each consisting of:
  a. A header with the file path (## File: path/to/file)
  b. The full contents of the file in a code block

## Usage Guidelines
- This file should be treated as read-only. Any changes should be made to the
  original repository files, not this packed version.
- When processing this file, use the file path to distinguish
  between different files in the repository.
- Be aware that this file may contain sensitive information. Handle it with
  the same level of security as you would the original repository.

## Notes
- Some files may have been excluded based on .gitignore rules and Repomix's configuration
- Binary files are not included in this packed representation. Please refer to the Repository Structure section for a complete list of file paths, including binary files
- Only files matching these patterns are included: app/**/*.{ts,tsx,js,jsx}, lib/**/*.{ts,tsx,js,jsx}, tests/**/*.{ts,tsx,js,jsx}, scripts/**/*.{ts,tsx,js,jsx}, drizzle/**/*.{ts,json,sql}, docs/**/*.md, *.config.{ts,js,cjs,mjs}, *.json, *.md
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
app/api/auth/login/route.ts
app/api/auth/logout/route.ts
app/api/auth/refresh/route.ts
app/api/auth/register/route.ts
app/api/health/live/route.ts
app/api/health/ready/route.ts
app/api/users/[id]/route.ts
app/api/users/route.ts
app/layout.tsx
app/page.tsx
development.md
docs/API_CONVENTIONS.md
docs/ARCHITECTURE.md
docs/NEXT16_WORLD_CLASS_BASELINE_SCOPE.md
docs/RUNBOOK.md
docs/TESTING.md
drizzle.config.ts
drizzle/0000_lush_prima.sql
drizzle/meta/_journal.json
drizzle/meta/0000_snapshot.json
lib/auth/jwt.ts
lib/auth/password.ts
lib/auth/session-security.ts
lib/auth/session-service.ts
lib/config/env.ts
lib/db/client.ts
lib/db/connection.ts
lib/db/schema.ts
lib/middleware/auth.ts
lib/middleware/rate-limit.ts
lib/observability/monitoring.ts
lib/platform/redis.ts
lib/types/index.ts
lib/utils/duration.ts
lib/utils/errors.ts
lib/utils/logger.ts
lib/utils/request.ts
lib/utils/response.ts
lib/validation/schemas.ts
next.config.js
package.json
postcss.config.js
QUICK_START.md
README.md
repomix.config.ts
tailwind.config.ts
tests/api/auth.test.ts
tests/api/users.test.ts
tests/integration/production-paths.test.ts
tests/load/smoke.js
tests/utils/http-utils.test.ts
tsconfig.json
vercel.json
vitest.config.ts
```

# Files

## File: app/api/auth/login/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { loginSchema } from '@/lib/validation/schemas';
import { db } from '@/lib/db/client';
import { verifyPassword } from '@/lib/auth/password';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { successResponse, errorResponse } from '@/lib/utils/response';
import { ValidationError, AuthenticationError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';
import { createSessionTokensForUser } from '@/lib/auth/session-service';
import { captureException } from '@/lib/observability/monitoring';

const DUMMY_PASSWORD_HASH = '$2b$10$CwTycUXWue0Thq9StjUM0uJ8R9mJ6Ck6A2Xb7xvFeoJq6Digw1k3a';
const LOGIN_IP_POLICY = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
  failOpen: false,
} as const;
const LOGIN_EMAIL_POLICY = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  failOpen: false,
} as const;

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';
  let attemptedEmail = 'unknown';

  try {
    // Rate limiting
    await checkRateLimit(`login:ip:${ip}`, LOGIN_IP_POLICY);

    if (!hasJsonContentType(request)) {
      throw new ValidationError('Content-Type must be application/json');
    }

    // Parse and validate input
    const body = await request.json();
    const validation = loginSchema.safeParse(body);

    if (!validation.success) {
      throw new ValidationError('Invalid input', { errors: validation.error.flatten() });
    }

    const { email, password } = validation.data;
    attemptedEmail = email.toLowerCase();
    await checkRateLimit(`login:email:${attemptedEmail}`, LOGIN_EMAIL_POLICY);

    logger.info('Login attempt', { email: attemptedEmail }, requestId);

    // Find user
    const user = await db.findUserByEmail(attemptedEmail);
    if (!user) {
      await verifyPassword(password, DUMMY_PASSWORD_HASH);
      await db.createAuditLog({
        eventType: 'auth.login_failure',
        severity: 'warn',
        requestId,
        ipAddress: ip,
        userAgent,
        metadata: { email: attemptedEmail, reason: 'unknown_user' },
      });
      throw new AuthenticationError('Invalid email or password');
    }

    // Verify password
    const isPasswordValid = await verifyPassword(password, user.passwordHash);
    if (!isPasswordValid) {
      await db.createAuditLog({
        userId: user.id,
        actorUserId: user.id,
        eventType: 'auth.login_failure',
        severity: 'warn',
        requestId,
        ipAddress: ip,
        userAgent,
        metadata: { email: attemptedEmail, reason: 'invalid_password' },
      });
      throw new AuthenticationError('Invalid email or password');
    }

    // Check if account is active
    if (user.status !== 'active') {
      throw new AuthenticationError(`Account is ${user.status}`);
    }

    const tokens = await createSessionTokensForUser(user, {
      ipAddress: ip,
      userAgent,
      requestId,
    });

    await db.createAuditLog({
      userId: user.id,
      actorUserId: user.id,
      eventType: 'auth.login_success',
      requestId,
      ipAddress: ip,
      userAgent,
      metadata: { email: user.email },
    });

    logger.info('Login successful', { userId: user.id }, requestId);

    return successResponse(
      {
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        token_type: tokens.tokenType,
        expires_in: tokens.expiresIn,
        refresh_expires_in: tokens.refreshExpiresIn,
        session_id: tokens.sessionId,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/login', email: attemptedEmail });
    logger.error('Login failed', details, requestId, {
      endpoint: '/api/auth/login',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/api/auth/logout/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { getTokenFromHeader } from '@/lib/auth/jwt';
import { revokeSessionByRefreshToken } from '@/lib/auth/session-service';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { AuthenticationError, getErrorDetails } from '@/lib/utils/errors';
import { errorResponse, successResponse } from '@/lib/utils/response';
import { getClientIp } from '@/lib/utils/request';
import { logger } from '@/lib/utils/logger';
import { captureException } from '@/lib/observability/monitoring';

const LOGOUT_RATE_LIMIT = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 30,
  failOpen: false,
} as const;

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    await checkRateLimit(`logout:ip:${ip}`, LOGOUT_RATE_LIMIT);

    const authHeader = request.headers.get('Authorization');
    const refreshToken = getTokenFromHeader(authHeader ?? undefined);
    if (!refreshToken) {
      throw new AuthenticationError('Refresh token required');
    }

    await revokeSessionByRefreshToken(refreshToken, {
      ipAddress: ip,
      userAgent,
      requestId,
    });

    return successResponse({ message: 'Logged out successfully' }, 200, requestId);
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/logout' });
    logger.error('Logout failed', details, requestId, {
      endpoint: '/api/auth/logout',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });
    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/api/auth/refresh/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { getTokenFromHeader } from '@/lib/auth/jwt';
import { rotateSessionTokens } from '@/lib/auth/session-service';
import { successResponse, errorResponse } from '@/lib/utils/response';
import { AuthenticationError, getErrorDetails } from '@/lib/utils/errors';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { getClientIp } from '@/lib/utils/request';
import { logger } from '@/lib/utils/logger';
import { captureException } from '@/lib/observability/monitoring';

const REFRESH_RATE_LIMIT = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 30,
  failOpen: false,
} as const;

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    await checkRateLimit(`refresh:ip:${ip}`, REFRESH_RATE_LIMIT);

    const authHeader = request.headers.get('Authorization');
    const token = getTokenFromHeader(authHeader ?? undefined);

    if (!token) {
      throw new AuthenticationError('Refresh token required');
    }

    const rotated = await rotateSessionTokens(token, {
      ipAddress: ip,
      userAgent,
      requestId,
    });

    logger.info('Token refreshed', { sessionId: rotated.sessionId }, requestId);

    return successResponse(
      {
        access_token: rotated.accessToken,
        refresh_token: rotated.refreshToken,
        token_type: rotated.tokenType,
        expires_in: rotated.expiresIn,
        refresh_expires_in: rotated.refreshExpiresIn,
        session_id: rotated.sessionId,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/refresh' });
    logger.error('Token refresh failed', details, requestId, {
      endpoint: '/api/auth/refresh',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });
    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/api/auth/register/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { createUserSchema } from '@/lib/validation/schemas';
import { db } from '@/lib/db/client';
import { hashPassword } from '@/lib/auth/password';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { successResponse, errorResponse } from '@/lib/utils/response';
import { ValidationError, ConflictError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';
import { createSessionTokensForUser } from '@/lib/auth/session-service';
import { captureException } from '@/lib/observability/monitoring';

const REGISTER_RATE_LIMIT = {
  windowMs: 60 * 60 * 1000,
  maxRequests: 5,
  failOpen: false,
} as const;

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    // Rate limiting
    await checkRateLimit(`register:ip:${ip}`, REGISTER_RATE_LIMIT);

    if (!hasJsonContentType(request)) {
      throw new ValidationError('Content-Type must be application/json');
    }

    // Parse and validate input
    const body = await request.json();
    const validation = createUserSchema.safeParse(body);

    if (!validation.success) {
      throw new ValidationError('Invalid input', { errors: validation.error.flatten() });
    }

    const email = validation.data.email.toLowerCase();
    const { name, password } = validation.data;

    logger.info('Registration attempt', { email }, requestId);

    // Check if user already exists
    const existingUser = await db.findUserByEmail(email);
    if (existingUser) {
      throw new ConflictError('Email already registered');
    }

    // Hash password
    const passwordHash = await hashPassword(password);

    // Create user
    const user = await db.createUser({
      email,
      name,
      passwordHash,
      role: 'user',
      status: 'active',
    });

    const tokens = await createSessionTokensForUser(user, {
      ipAddress: ip,
      userAgent,
      requestId,
    });

    await db.createAuditLog({
      userId: user.id,
      actorUserId: user.id,
      eventType: 'auth.register_success',
      requestId,
      ipAddress: ip,
      userAgent,
      metadata: { email: user.email },
    });

    logger.info('User registered successfully', { userId: user.id }, requestId);

    return successResponse(
      {
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
        },
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        token_type: tokens.tokenType,
        expires_in: tokens.expiresIn,
        refresh_expires_in: tokens.refreshExpiresIn,
        session_id: tokens.sessionId,
      },
      201,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/register' });
    logger.error('Registration failed', details, requestId, {
      endpoint: '/api/auth/register',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/api/health/live/route.ts
````typescript
import { successResponse } from '@/lib/utils/response';

export async function GET() {
  const requestId = crypto.randomUUID();
  return successResponse(
    {
      status: 'ok',
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
    },
    200,
    requestId
  );
}
````

## File: app/api/health/ready/route.ts
````typescript
import { db } from '@/lib/db/client';
import { checkRedisHealth } from '@/lib/platform/redis';
import { errorResponse, successResponse } from '@/lib/utils/response';
import { logger } from '@/lib/utils/logger';

export async function GET() {
  const requestId = crypto.randomUUID();
  const [databaseReady, redisReady] = await Promise.all([db.healthCheck(), checkRedisHealth()]);
  const isReady = databaseReady && redisReady;

  if (!isReady) {
    logger.error(
      'Readiness probe failed',
      {
        databaseReady,
        redisReady,
      },
      requestId,
      { endpoint: '/api/health/ready', status: 503 }
    );

    return errorResponse(
      'SERVICE_UNAVAILABLE',
      'Service dependencies are not ready',
      503,
      {
        dependencies: {
          database: databaseReady ? 'ready' : 'unavailable',
          redis: redisReady ? 'ready' : 'unavailable',
        },
      },
      requestId
    );
  }

  return successResponse(
    {
      status: 'ready',
      dependencies: {
        database: 'ready',
        redis: 'ready',
      },
    },
    200,
    requestId
  );
}
````

## File: app/api/users/[id]/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { updateUserSchema } from '@/lib/validation/schemas';
import { db } from '@/lib/db/client';
import { extractUser, requireAuth, requireRole, requireActiveStatus } from '@/lib/middleware/auth';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { successResponse, errorResponse } from '@/lib/utils/response';
import { ValidationError, NotFoundError, AuthorizationError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';
import { captureException } from '@/lib/observability/monitoring';

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const requestId = crypto.randomUUID();
  const { id } = await params;
  const startTime = Date.now();
  const ip = getClientIp(request);

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireActiveStatus(user);

    // Authorization: can only view own profile or if admin
    if (user.id !== id && !['admin', 'superadmin'].includes(user.role)) {
      throw new AuthorizationError('You can only view your own profile');
    }

    logger.info('Fetching user details', { userId: id }, requestId);

    // Fetch user
    const targetUser = await db.findUserById(id);
    if (!targetUser) {
      throw new NotFoundError('User not found');
    }

    return successResponse(
      {
        id: targetUser.id,
        email: targetUser.email,
        name: targetUser.name,
        role: targetUser.role,
        status: targetUser.status,
        createdAt: targetUser.createdAt,
        updatedAt: targetUser.updatedAt,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users/[id]:GET', userId: id });
    logger.error('Failed to fetch user', details, requestId, {
      endpoint: '/api/users/[id]:GET',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}

export async function PATCH(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const requestId = crypto.randomUUID();
  const { id } = await params;
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireActiveStatus(user);

    // Authorization: can only update own profile or if admin
    if (user.id !== id && !['admin', 'superadmin'].includes(user.role)) {
      throw new AuthorizationError('You can only update your own profile');
    }

    if (!hasJsonContentType(request)) {
      throw new ValidationError('Content-Type must be application/json');
    }

    const body = await request.json();

    // Validate input
    const validation = updateUserSchema.safeParse(body);
    if (!validation.success) {
      throw new ValidationError('Invalid input', { errors: validation.error.flatten() });
    }

    if (validation.data.role && !['admin', 'superadmin'].includes(user.role)) {
      throw new AuthorizationError('Only admins can update user roles');
    }

    const existing = await db.findUserById(id);
    if (!existing) {
      throw new NotFoundError('User not found');
    }

    logger.info('Updating user', { userId: id }, requestId);

    // Update user
    const updated = await db.updateUser(id, validation.data);
    if (!updated) {
      throw new NotFoundError('User not found');
    }

    if (validation.data.role || validation.data.status) {
      await db.createAuditLog({
        userId: updated.id,
        actorUserId: user.id,
        eventType: 'users.privileged_update',
        requestId,
        ipAddress: ip,
        userAgent,
        metadata: {
          previousRole: existing.role,
          newRole: updated.role,
          previousStatus: existing.status,
          newStatus: updated.status,
        },
      });
    }

    return successResponse(
      {
        id: updated.id,
        email: updated.email,
        name: updated.name,
        role: updated.role,
        status: updated.status,
        createdAt: updated.createdAt,
        updatedAt: updated.updatedAt,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users/[id]:PATCH', userId: id });
    logger.error('Failed to update user', details, requestId, {
      endpoint: '/api/users/[id]:PATCH',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const requestId = crypto.randomUUID();
  const { id } = await params;
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireRole(user, 'admin', 'superadmin');

    const targetUser = await db.findUserById(id);
    if (!targetUser) {
      throw new NotFoundError('User not found');
    }

    logger.info('Deleting user', { userId: id }, requestId);

    // Delete user
    const deleted = await db.deleteUser(id);
    if (!deleted) {
      throw new NotFoundError('User not found');
    }

    await db.createAuditLog({
      userId: id,
      actorUserId: user.id,
      eventType: 'users.deleted',
      severity: 'warn',
      requestId,
      ipAddress: ip,
      userAgent,
      metadata: {
        deletedUserEmail: targetUser.email,
        deletedUserRole: targetUser.role,
      },
    });

    return successResponse({ message: 'User deleted successfully' }, 200, requestId);
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users/[id]:DELETE', userId: id });
    logger.error('Failed to delete user', details, requestId, {
      endpoint: '/api/users/[id]:DELETE',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/api/users/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { paginationSchema } from '@/lib/validation/schemas';
import { db } from '@/lib/db/client';
import { extractUser, requireAuth, requireRole } from '@/lib/middleware/auth';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { paginatedResponse, errorResponse } from '@/lib/utils/response';
import { ValidationError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { getClientIp } from '@/lib/utils/request';
import { captureException } from '@/lib/observability/monitoring';

export async function GET(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);

  try {
    // Rate limiting
    await checkRateLimit(`users:ip:${ip}`, { failOpen: true });

    // Authentication
    const user = await extractUser(request);
    requireAuth(user);
    requireRole(user, 'admin', 'superadmin');

    // Parse query parameters
    const url = new URL(request.url);
    const queryData = {
      page: url.searchParams.get('page'),
      limit: url.searchParams.get('limit'),
      search: url.searchParams.get('search') ?? undefined,
    };

    const validation = paginationSchema.safeParse(queryData);
    if (!validation.success) {
      throw new ValidationError('Invalid query parameters', { errors: validation.error.flatten() });
    }

    const { page, limit, search } = validation.data;

    logger.info('Fetching users list', { page, limit, search }, requestId);

    // Fetch users
    const result = search ? await db.searchUsers(search, page, limit) : await db.getAllUsers(page, limit);

    return paginatedResponse(
      result.users.map((u) => ({
        id: u.id,
        email: u.email,
        name: u.name,
        role: u.role,
        status: u.status,
        createdAt: u.createdAt,
        updatedAt: u.updatedAt,
      })),
      page,
      limit,
      result.total,
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/users' });
    logger.error('Failed to fetch users', details, requestId, {
      endpoint: '/api/users',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/layout.tsx
````typescript
import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SwissKnife - Backend-First Next.js Template',
  description: 'Compact backend-first template with authentication, users API, validation, and middleware foundations.',
  keywords: ['swissknife', 'nextjs', 'typescript', 'api-template', 'authentication'],
  authors: [{ name: 'SwissKnife' }],
  icons: {
    icon: '/favicon.ico',
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  maximumScale: 1,
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="bg-background text-foreground antialiased">
        {children}
      </body>
    </html>
  );
}
````

## File: app/page.tsx
````typescript
export default function Home() {
  return (
    <main className="mx-auto min-h-screen max-w-5xl px-4 py-16">
      <section className="rounded-lg border border-border bg-secondary/20 p-8">
        <p className="mb-3 text-xs uppercase tracking-wider text-muted-foreground">SwissKnife</p>
        <h1 className="mb-4 text-3xl font-bold tracking-tight md:text-4xl">Backend-first Next.js template</h1>
        <p className="max-w-3xl text-muted-foreground">
          This starter keeps only essentials: authentication routes, user routes, validation, error handling, and shared middleware.
        </p>
      </section>

      <section className="mt-8 grid gap-4 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-secondary/20 p-6">
          <h2 className="mb-3 text-lg font-semibold">Core API</h2>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li><code>POST /api/auth/register</code></li>
            <li><code>POST /api/auth/login</code></li>
            <li><code>POST /api/auth/refresh</code></li>
            <li><code>POST /api/auth/logout</code></li>
            <li><code>GET /api/users</code></li>
            <li><code>GET /api/users/[id]</code></li>
            <li><code>PATCH /api/users/[id]</code></li>
            <li><code>DELETE /api/users/[id]</code></li>
            <li><code>GET /api/health/live</code></li>
            <li><code>GET /api/health/ready</code></li>
          </ul>
        </div>

        <div className="rounded-lg border border-border bg-secondary/20 p-6">
          <h2 className="mb-3 text-lg font-semibold">Run Locally</h2>
          <div className="rounded-md bg-background p-3 font-mono text-sm">
            <p>cp .env.example .env.local</p>
            <p>corepack pnpm install</p>
            <p>corepack pnpm dev</p>
          </div>
        </div>
      </section>
    </main>
  );
}
````

## File: development.md
````markdown
# SwissKnife — Development Plan

## What This Is

SwissKnife is a backend-first Next.js App Router starter. Not a framework. Not a platform.
A chassis — tight, correct, secure by default — that any developer can build on without
ripping out the foundation first.

The measure of done: a developer clones this, reads it for 10 minutes, and says
"yeah, this is how I'd have built it myself." No red flags. No gotchas. No day-one fixes.

This document is the source of truth. Read it before touching anything.

---

## Current State — Honest Assessment

The architecture is sound. Route pipeline is consistent. Error class hierarchy is clean.
Zod schemas are well-defined. `jose` JWT is the right choice. CI exists. Types are coherent.

What's broken is specific. 6 security issues, 6 correctness bugs, 8 design gaps.
None of them require structural changes. All of them are fixable inside the existing files.

The MockDatabase stays. It's the test harness. We work around it, not against it.

---

## The 10 Developers This Serves

Before any fix, the question is: does this make one of these 10 developers' lives better?
If not, it doesn't belong in a chassis.

| Dev | Scenario | What they need |
|-----|----------|----------------|
| 1 | Solo SaaS MVP | Auth that works, `userId` on every resource, `requireAuth` they can drop anywhere |
| 2 | Agency, client portals | Predictable structure, consistent error shape, debuggable request traces |
| 3 | Multi-tenant B2B startup | Role system that's extensible, not hardcoded |
| 4 | Fintech, security-conscious | No privilege escalation bugs, proper token hygiene, audit-ready |
| 5 | Mobile backend | Short-lived tokens + refresh — 7d access tokens are a non-starter for mobile |
| 6 | OSS maintainer | Code clean enough that contributors don't ask questions |
| 7 | API layer for existing frontend | Error shape locked and typed so frontend team can work independently |
| 8 | Internal tool dev | Safe defaults — disabling rate limiting shouldn't be silent |
| 9 | Contractor, greenfield API | No day-one security fixes required, just build |
| 10 | Tech lead evaluating starters | No architectural landmines that bite the team in 6 months |

Eight of ten scenarios converge on the same four problems:
the login timing attack, the self-register-as-admin bug, the broken requestId trace,
and the JWT carrying live role/status with a 7-day expiry and no refresh.

Everything in this plan comes from that convergence.

---

## Issues Found — Full Audit

### Security

**S1 — Timing attack on login** (`app/api/auth/login/route.ts`)
`findUserByEmail` returns early when user not found, so `verifyPassword` never runs.
Attacker measures response time to enumerate valid emails.
Fix: always run `verifyPassword` against a constant dummy hash when user is not found.

**S2 — Self-register as admin** (`app/api/auth/register/route.ts`)
`createUserSchema` accepts `role: z.enum(['user', 'admin'])` from the request body.
Any client can POST `{"role": "admin"}` and get admin access. Critical privilege escalation.
Fix: hardcode `role: 'user'` in the register handler. Ignore client-supplied role entirely.

**S3 — JWT carries live role and status** (`lib/middleware/auth.ts`)
`extractUser` reconstructs the user from token payload — role, status, everything.
A suspended or demoted user keeps full access until token expiry. With `JWT_EXPIRY=7d`
that's a 7-day window of incorrect permissions with no way to close it.
Fix: either document this tradeoff explicitly so devs building on top make informed decisions,
or add a lightweight DB lookup on sensitive routes. Decision must be made and committed to —
silent landmine is not an option.

**S4 — No per-email rate limiting on login** (`lib/middleware/rate-limit.ts`)
Rate limiting is per-IP only. A targeted attack against one email across rotating IPs bypasses it.
Fix: add per-email rate limiting in the login handler in addition to per-IP.
Key: `login:email:${email}` with a stricter limit (5 attempts per 15 minutes).

**S5 — `x-forwarded-for` is spoofable** (`app/api/auth/login/route.ts` and others)
The rate limiter keys off a header any client can forge. Behind a real load balancer
the balancer overwrites it and this is fine. Deployed directly it's bypassed trivially.
Fix: document the assumption explicitly. Add a note in `.env.example` and `RUNBOOK.md`:
"TRUST_PROXY must match your deployment — if running behind a load balancer, the balancer
must set x-forwarded-for. If running directly, IP-based rate limiting is not reliable."

**S6 — `RATE_LIMIT_ENABLED=false` is silent** (`lib/middleware/rate-limit.ts`)
Setting this in prod disables all rate limiting with no log, no warning, nothing.
Fix: log a `warn` on startup when rate limiting is disabled.

### Correctness

**C1 — requestId is two different values** (`lib/utils/response.ts`, all route handlers)
Every route generates `const requestId = crypto.randomUUID()` at the top and passes it
to logger calls. But `successResponse()` and `errorResponse()` generate a new UUID internally.
The requestId in your logs and the requestId in the API response are different values.
Tracing is broken silently. Every debuggable incident is harder than it needs to be.
Fix: accept `requestId` as a parameter in `successResponse`, `paginatedResponse`,
and `errorResponse`. Pass the route-level requestId through.

**C2 — `updatedAt` is always now** (`lib/middleware/auth.ts`)
`extractUser` reconstructs user with `updatedAt: new Date()` — the current request time,
not the actual field value. This fake timestamp gets returned in API responses.
Fix: remove `updatedAt` from the JWT-reconstructed user object or accept it will be
approximate and document it. Don't silently return a lie.

**C3 — User IDs use `Math.random()`** (`lib/db/client.ts`)
`user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}` — `Math.random()` is not
cryptographically random. Low but nonzero collision probability under concurrent load.
`crypto.randomUUID()` is already imported and used elsewhere in the codebase.
Fix: use `crypto.randomUUID()` for user ID generation. One line.

**C4 — `verifyToken` throws plain `Error`** (`lib/auth/jwt.ts`)
The catch in `verifyToken` throws `new Error('Invalid or expired token')`.
In `extractUser`, the catch re-wraps it as `AuthenticationError` but the original message
is swallowed — replaced with `'Failed to verify token'`. Stack traces lose context.
Fix: throw `AuthenticationError` directly from `verifyToken`.

**C5 — Env vars have no validation** (`lib/config/env.ts`)
`parseInt(process.env.RATE_LIMIT_WINDOW_MS || '3600000')` — if set to `abc` it silently
becomes `NaN`. The rate limiter then behaves unpredictably. `JWT_SECRET` being undefined
won't crash until a request is made, not at startup.
Fix: wrap env parsing in Zod. Throw on startup if invalid. Zod is already installed.

**C6 — PATCH validates after reading `body.role`** (`app/api/users/[id]/route.ts`)
```ts
const body = await request.json();
if (body.role && !['admin', 'superadmin'].includes(user.role)) { ... }
const validation = updateUserSchema.safeParse(body);
```
Role check happens on unvalidated raw body before Zod runs.
Fix: validate first, then check intent on the validated data.

### Design

**D1 — IP extraction duplicated in every route handler**
Six times across four files:
```ts
const ipAddress = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
checkRateLimit(`login:${ipAddress}`);
```
Fix: extract `getClientIp(request)` as a shared helper in `lib/utils/request.ts`.
One function, one place, one change if the logic ever needs updating.

**D2 — `meta` is optional in `ApiResponse<T>`**
`meta?` means every consumer has to null-check it. It's always sent. The type is lying.
Fix: remove the `?`. `meta` is required. Align the type with the actual behavior.

**D3 — No `X-Request-Id` response header**
requestId is in the response body. It should also be a response header so frontend devs
and API consumers can log it without parsing the body. Standard practice.
Fix: set `X-Request-Id` header on every response alongside the body field.

**D4 — Security headers are API-only** (`next.config.js`)
`headers()` only applies to `/api/:path*`. The app shell has no security headers at all.
Fix: add global headers — `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: strict-origin-when-cross-origin`, `X-XSS-Protection: 0` (modern browsers
don't need it, old ones it helps) — across all routes, not just API.

**D5 — No `Content-Type` validation on request body**
Routes call `request.json()` without checking `Content-Type: application/json`.
Non-JSON bodies throw an unhandled parse error that becomes a generic 500.
Fix: check `Content-Type` header before calling `.json()`. Return a clean 400 if wrong.

**D6 — `JWT_EXPIRY=7d` with no refresh mechanism**
7-day access tokens are a non-starter for mobile, and a real risk if tokens are leaked.
This is the most common reason devs building on this starter have to immediately add their
own auth layer on top — which defeats the purpose.
Fix: add `/api/auth/refresh` route. Short-lived access tokens (15min default).
Refresh tokens stored in DB (MockDatabase already has the interface for extension).
This is the one new file this plan adds.

**D7 — `AuthToken` interface is dead** (`lib/types/index.ts`)
Defined, exported, never used. Login and register return inline objects.
Fix: either use it in the route return types or delete it.

**D8 — `API_BASE_URL` in env is dead config** (`lib/config/env.ts`, `vercel.json`)
In `env.ts`, in `vercel.json` env list, not imported or used anywhere.
Fix: remove it from both places.

---

## Implementation Plan

No new architecture. No new directories. No rearranging what works.
Every change is inside an existing file, except one new route and one new util.

Work in this order. Each item is a complete unit — finish it, verify it, move to next.

---

### 1. Env validation (`lib/config/env.ts`)

Do this first. Everything downstream depends on env being trustworthy.

```ts
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  VERCEL_ENV: z.string().default('development'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),
  DATABASE_URL: z.string().url().optional(),
  RATE_LIMIT_ENABLED: z.coerce.boolean().default(true),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().positive().default(3_600_000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().positive().default(100),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  console.error('[env] Invalid environment variables:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const env = parsed.data;
export function isProductionEnvironment() {
  return env.NODE_ENV === 'production' || env.VERCEL_ENV === 'production';
}
```

Also update `.env.example`: change `JWT_EXPIRY=7d` to `JWT_EXPIRY=15m`,
add `JWT_REFRESH_EXPIRY=7d`, change `JWT_SECRET` comment to note 32-char minimum.
Remove `API_BASE_URL` from `.env.example` and from `vercel.json` env list.

Exit condition: app refuses to start if `JWT_SECRET` is missing or under 32 chars.

---

### 2. Shared request util (`lib/utils/request.ts`) — new file

Small but eliminates 6 copy-pastes and centralizes IP logic.

```ts
import { type NextRequest } from 'next/server';

export function getClientIp(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}
```

Note: `x-forwarded-for` can be a comma-separated list when behind multiple proxies.
Take the first value only — that's the original client IP.

After creating this, replace all six instances of the IP extraction block in the routes
with `import { getClientIp } from '@/lib/utils/request'` and `getClientIp(request)`.

---

### 3. Fix requestId threading (`lib/utils/response.ts`)

Add `requestId` parameter to all three response helpers:

```ts
export function successResponse<T>(data: T, status: number = 200, requestId?: string) { ... }
export function paginatedResponse<T>(..., requestId?: string) { ... }
export function errorResponse(code: string, message: string, status: number, details?: Record<string, unknown>, requestId?: string) { ... }
```

Inside each: use the passed `requestId` if provided, fall back to `crypto.randomUUID()` if not.
Also set `X-Request-Id` as a response header:

```ts
return NextResponse.json(response, {
  status,
  headers: { 'X-Request-Id': response.meta.requestId },
});
```

Then update every route to pass its `requestId` into the response helper calls.

Exit condition: log requestId and response requestId match on every request.

---

### 4. Fix `verifyToken` error chain (`lib/auth/jwt.ts`)

```ts
import { AuthenticationError } from '@/lib/utils/errors';

export async function verifyToken(token: string) {
  try {
    const verified = await jwtVerify(token, getJwtSecret());
    return verified.payload;
  } catch {
    throw new AuthenticationError('Invalid or expired token');
  }
}
```

This means `extractUser` no longer needs its own re-wrapping catch. Simplify accordingly.

---

### 5. Fix timing attack on login (`app/api/auth/login/route.ts`)

```ts
const DUMMY_HASH = '$2a$10$dummy.hash.for.timing.attack.prevention.padding';

// in the handler:
const user = await db.findUserByEmail(email);

if (!user) {
  // Run a dummy comparison to normalize response time
  await verifyPassword('dummy', DUMMY_HASH);
  throw new AuthenticationError('Invalid email or password');
}
```

The dummy hash must be a real bcrypt hash (pre-computed, constant) so the timing
characteristics match a real comparison. Generate it once:
`bcrypt.hashSync('dummy', 10)` and paste the result as the constant.

---

### 6. Fix self-register as admin (`app/api/auth/register/route.ts`)

Remove `role` from `createUserSchema` entirely, or keep it for internal use
but never apply it from the request body in the register route:

```ts
const user = await db.createUser({
  email,
  name,
  passwordHash,
  role: 'user', // always. never trust client-supplied role on registration.
  status: 'active',
});
```

If admin creation is needed, it goes through an admin-only endpoint, not public registration.

---

### 7. Fix PATCH validation order (`app/api/users/[id]/route.ts`)

Move Zod validation before the role check:

```ts
const body = await request.json();

// Validate first
const validation = updateUserSchema.safeParse(body);
if (!validation.success) {
  throw new ValidationError('Invalid input', { errors: validation.error.flatten() });
}

// Then check intent on validated data
if (validation.data.role && !['admin', 'superadmin'].includes(user.role)) {
  throw new AuthorizationError('Only admins can update user roles');
}
```

---

### 8. Fix user ID generation (`lib/db/client.ts`)

```ts
// before
const id = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

// after
const id = crypto.randomUUID();
```

---

### 9. Fix `meta` type and clean dead types (`lib/types/index.ts`)

Make `meta` required in `ApiResponse<T>`:
```ts
meta: {        // was meta?
  timestamp: string;
  requestId: string;
};
```

Delete `AuthToken` interface — it's defined but never used anywhere.
When the refresh token route is added (step 10), define the return type inline or
create a proper `TokenPair` interface at that point.

Remove `API_BASE_URL` from `env.ts` env object since it's unused.

---

### 10. Per-email rate limiting on login (`app/api/auth/login/route.ts`)

After the IP-based check, add:

```ts
checkRateLimit(`login:ip:${ip}`);       // existing, broad
checkRateLimit(`login:email:${email}`, 60_000, 5); // new, strict — 5 per minute per email
```

This requires `createRateLimitMiddleware` to be called with tighter params for email-specific
limiting. Pass window and max as arguments rather than using the default singleton for this case.

---

### 11. Rate limit disabled warning (`lib/middleware/rate-limit.ts`)

```ts
if (!env.RATE_LIMIT_ENABLED) {
  logger.warn('Rate limiting is disabled. Do not use this setting in production.');
  return () => true;
}
```

---

### 12. Security headers (`next.config.js`)

Replace the current headers config with:

```js
headers: async () => [
  {
    source: '/(.*)',
    headers: [
      { key: 'X-Frame-Options', value: 'DENY' },
      { key: 'X-Content-Type-Options', value: 'nosniff' },
      { key: 'X-XSS-Protection', value: '0' },
      { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
      { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
    ],
  },
  {
    source: '/api/(.*)',
    headers: [
      { key: 'Content-Type', value: 'application/json' },
    ],
  },
],
```

`X-XSS-Protection: 0` is correct for modern browsers — the old `1; mode=block` can
introduce vulnerabilities in some cases. Set to 0 and let CSP do the work.

---

### 13. Add `/api/auth/refresh` route — the one new file

`app/api/auth/refresh/route.ts`

This is the only net-new file in the entire plan. Completes the auth story.
Without it, the starter is not usable for mobile or any long-running session.

```ts
import { type NextRequest } from 'next/server';
import { verifyToken, signToken, getTokenFromHeader } from '@/lib/auth/jwt';
import { successResponse, errorResponse } from '@/lib/utils/response';
import { AuthenticationError, getErrorDetails } from '@/lib/utils/errors';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { getClientIp } from '@/lib/utils/request';
import { logger } from '@/lib/utils/logger';

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();

  try {
    const ip = getClientIp(request);
    checkRateLimit(`refresh:ip:${ip}`);

    const authHeader = request.headers.get('Authorization');
    const token = getTokenFromHeader(authHeader ?? undefined);

    if (!token) {
      throw new AuthenticationError('Refresh token required');
    }

    // Verify the refresh token
    const payload = await verifyToken(token);

    if (!payload.sub || !payload.email || payload.type !== 'refresh') {
      throw new AuthenticationError('Invalid refresh token');
    }

    // Issue new access token
    const accessToken = await signToken(
      {
        sub: payload.sub,
        email: payload.email,
        name: payload.name,
        role: payload.role,
        status: payload.status,
        type: 'access',
      },
      process.env.JWT_EXPIRY ?? '15m'
    );

    logger.info('Token refreshed', { userId: payload.sub }, requestId);

    return successResponse(
      {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: 15 * 60,
      },
      200,
      requestId
    );
  } catch (error) {
    const details = getErrorDetails(error);
    logger.error('Token refresh failed', details, requestId);
    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
```

Also update login and register to issue both an access token and a refresh token.
Add `type: 'access'` and `type: 'refresh'` claims to distinguish them.
Access token: `JWT_EXPIRY` (default 15m). Refresh token: `JWT_REFRESH_EXPIRY` (default 7d).

---

### 14. Document the JWT role/status tradeoff

This is a decision, not a bug. But it must be documented.

Add to `docs/ARCHITECTURE.md` (or create it if stale):

```md
## Auth — Token Role/Status Tradeoff

User role and status are embedded in the JWT at issue time. This means:
- A user's role or status change does not take effect until their current token expires.
- Default access token expiry is 15 minutes, so the maximum drift window is 15 minutes.
- If immediate revocation is required (e.g. security incident), the JWT secret must be rotated,
  which invalidates all active tokens for all users.

This is an intentional tradeoff: no DB lookup on every request, at the cost of eventual
consistency on role/status changes. For most applications this is acceptable.
If your use case requires immediate revocation, add a token blocklist (Redis recommended)
and check it in `extractUser` before returning the user object.
```

---

## What Doesn't Change

- File structure — no moves, no renames
- MockDatabase — test harness, untouched
- Error class hierarchy — already correct
- Route pipeline order — already correct
- Zod validation schemas — already correct
- CI pipeline — already runs `verify`
- `vercel.json` — correct except `API_BASE_URL` removal

---

## Definition of Done

Every item in the implementation plan is complete when:

1. The specific file compiles without TypeScript errors
2. `pnpm verify` passes (type-check + lint + build)
3. The issue it fixes cannot be reproduced

The overall plan is complete when:

- A developer can register, login, get a token, refresh it, and hit a protected route
  in a single `curl` session with no setup beyond cloning and setting env vars
- A security engineer reading the code finds no unacknowledged vulnerabilities
- Every log line and its corresponding API response carry the same `requestId`
- The app refuses to start with an invalid or missing `JWT_SECRET`
- No route handler duplicates logic that exists in a shared util

---

## Working Rules

- Read this file before planning or editing any file in the codebase
- Don't add features — tighten what exists
- Don't move files — the structure is correct
- Every change must close a specific issue from the audit above
- If you find a new issue, add it to the audit section before fixing it
- MockDatabase is the test harness — do not modify it to paper over issues
- When done with this plan, the next document governs what gets built on top
````

## File: docs/NEXT16_WORLD_CLASS_BASELINE_SCOPE.md
````markdown
# Next.js 16 World-Class Baseline Scope (App Router)

This document defines a practical, production-ready baseline for evolving this codebase into a "10/10" starter for real-world teams.

## Goals

- Provide a **minimal-reinvention** architecture.
- Set **must-have** standards for security, reliability, and DX.
- Keep implementation scope realistic for phased delivery.

## Current Snapshot (from this repo)

Strengths already present:
- App Router route handlers are structured with validation, logging, and error normalization.
- Auth + RBAC concepts already exist.
- API docs and admin UI exist as a developer onboarding aid.

Gaps to close:
- In-memory database and rate limiter are not production-safe for multi-instance deployments.
- Tooling is not fully green (TypeScript/lint dependency gaps).
- Documentation/setup consistency can be improved.

---

## Architecture Baseline (Next.js 16)

### 1) Runtime & rendering strategy
- Default to **Server Components** for data-heavy UI.
- Use Client Components only for interactive islands.
- Use Route Handlers for backend APIs and server-side orchestration.
- Adopt explicit caching rules per route (`force-cache`, `no-store`, revalidation windows).

### 2) Domain-oriented module layout
Keep App Router pages thin and move logic to domain modules.

Suggested structure:

```txt
app/
  (marketing)/
  (app)/
  api/
    auth/
    users/
lib/
  domain/
    users/
      service.ts
      repository.ts
      policy.ts
      schema.ts
    auth/
      service.ts
      policy.ts
      schema.ts
  platform/
    db/
    cache/
    queue/
    telemetry/
  shared/
    errors/
    response/
    validation/
```

### 3) API contract standard
- Keep a single response envelope style for success/error.
- Generate OpenAPI from source-of-truth schemas (Zod).
- Add contract tests to prevent drift.

---

## What to Use vs What Not to Rebuild

## Use proven building blocks
- Auth/session: Auth.js or managed auth (Clerk/Supabase/Auth0) unless deep custom requirements.
- DB: Postgres + Prisma or Drizzle.
- Rate limiting: Redis/Upstash-backed distributed limiter.
- Background jobs: queue provider (e.g., Upstash QStash / Cloud Tasks / BullMQ).
- Observability: OpenTelemetry + Sentry/Datadog.

## Avoid reinventing
- Custom crypto/session token stores without threat modeling.
- Homegrown distributed rate-limiting.
- Ad-hoc migrations or SQL runbooks without tooling.
- Manual production incident workflows without instrumentation.

---

## Security Baseline (Required)

- Secure cookies for web auth flows (`httpOnly`, `secure`, `sameSite`).
- CSP, HSTS, X-Content-Type-Options, Referrer-Policy.
- Input validation on every external boundary.
- Password policy + reset flow + email verification.
- Optional MFA/passkeys for admin users.
- Secret rotation playbook and key versioning.
- Dependency scanning + SAST in CI.

### Authorization baseline
- Keep RBAC, but add policy checks in domain layer (not UI-only).
- Add audit logs for admin/security-sensitive actions.

---

## Data & Persistence Baseline

- Move to durable Postgres storage.
- Add migration pipeline (dev/preview/prod).
- Add unique constraints and critical indexes.
- Include idempotency keys for write endpoints where retries can happen.
- Add soft-delete or archival strategy for user/admin data.

---

## Reliability & Operations Baseline

### Observability
- Structured logs with request IDs and user IDs (when authenticated).
- Distributed traces across route handlers and DB calls.
- RED metrics per endpoint (rate/errors/duration).
- Error budget + SLO draft for critical endpoints.

### Runtime hardening
- Health endpoints split into liveness/readiness.
- Graceful failure paths for DB/cache/queue outages.
- Retry policies with backoff and dead-letter queue for jobs.

---

## Performance Baseline

- P95 latency budget per route category (auth/read/write).
- Query optimization + pagination limits + index review.
- Bundle analysis and client JS budget for interactive routes.
- Caching plan:
  - Request cache for stable reads.
  - Edge cache for public content.
  - Invalidation strategy for mutable resources.

---

## Quality Baseline (CI/CD)

Required merge gates:
- `type-check`
- `lint`
- `test:unit`
- `test:integration`
- `build`
- security scan (dependencies)

Release flow:
- Preview deployments on PR.
- Database migration checks on preview.
- Post-deploy smoke tests.
- Rollback instructions documented.

---

## Testing Strategy (baseline standard)

- Unit tests: pure domain/service/validation logic.
- Integration tests: route handlers + DB + auth checks.
- E2E tests: critical user journeys (register/login/admin user lifecycle).
- Contract tests: ensure API response format remains stable.

Target confidence:
- 100% of critical auth paths covered by integration/E2E.
- Load smoke for login/users list endpoints.

---

## Next.js 16 Migration/Readiness Checklist

- Replace deprecated lint integrations with ESLint CLI workflow.
- Review all Server/Client component boundaries.
- Confirm route handler runtime targets (Node vs Edge) per endpoint.
- Add instrumentation hook compatible with current Next runtime guidance.
- Validate cache tags/revalidation for data paths.

---

## Phased Execution Plan

## Phase 1 (Foundation, 1-2 weeks)
- Fix type/lint green baseline.
- Introduce Postgres + ORM with initial migrations.
- Replace in-memory rate limiter with Redis-backed limiter.
- Add CI required checks.

**Exit criteria**
- All checks green on PRs.
- No in-memory-only production path for auth/users/rate limits.

## Phase 2 (Security + Ops, 1-2 weeks)
- Harden auth/session flows and account recovery.
- Add observability stack (logs/traces/errors).
- Add audit logs for privileged actions.

**Exit criteria**
- Security baseline checklist complete.
- Dashboards + alerts for core APIs active.

## Phase 3 (Scale + DX, 1-2 weeks)
- Add contract tests and performance budgets.
- Improve generators/templates for new modules.
- Publish ADRs and runbook updates.

**Exit criteria**
- New endpoints follow template automatically.
- Team onboarding path is reproducible in <30 minutes.

---

## Practical "Do/Don't" for this codebase

### Do
- Keep route handlers thin.
- Keep validation schemas close to domain modules.
- Centralize error typing/serialization.
- Prefer managed/proven infra for auth/session/rate limit.

### Don't
- Expand mock/in-memory implementations for production pathways.
- Put authorization checks only in UI.
- Couple response formatting to page components.
- Add new endpoints without tests and observability hooks.

---

## Definition of Done for "10/10 baseline"

A release qualifies when:
1. Security baseline is complete and validated.
2. CI/CD gates prevent regressions.
3. Persistence and rate-limiting are distributed and durable.
4. Core flows are covered by integration + E2E tests.
5. Incidents are diagnosable within minutes via logs/traces/alerts.
6. New team members can bootstrap and ship a safe endpoint quickly.


## Router/Framework Patterns Worth Borrowing

Even while staying on Next.js App Router, borrow proven ideas:

- **Remix-style mutations**: co-locate mutation handling with strong server validation and predictable error surfaces.
- **Fastify/Nest API discipline**: explicit DTO/schema contracts and lifecycle hooks for logging/metrics.
- **Rails/Laravel conventions**: batteries-included runbooks, migrations, and one-command onboarding.

Takeaway: keep Next.js for UI/platform fit, but adopt stronger backend conventions where helpful.
````

## File: docs/TESTING.md
````markdown
# Testing

## Commands
```bash
npm run test
npm run test:unit
npm run test:integration
npm run verify
```

`verify` runs:
1. Type generation and TypeScript checks
2. ESLint
3. Unit Vitest suite
4. Next.js production build check

## Security Note on `verify`
- Route code validates `JWT_SECRET` at runtime.
- For local verification convenience, the verify build command injects a temporary `JWT_SECRET` only when your shell does not define one.
- This does not relax runtime security requirements for `dev`, `start`, or deployed environments.

## Current Test Focus
- Auth routes:
  - role escalation prevention on register
  - generic login failure behavior
  - refresh token type enforcement
  - refresh token rotation and reuse detection
  - logout revocation behavior
- Users routes:
  - auth and role authorization boundaries
  - content-type validation
  - validation order before authorization checks
  - admin-only role update behavior
- Integration:
  - postgres-backed repository path
  - readiness endpoint dependency checks
- Utility helpers:
  - response envelope requestId threading
  - pagination/error response shape
  - client IP and JSON content-type request parsing

## Writing New Tests
- Keep tests under `tests/**/*.test.ts`.
- Use `resetMockDatabase()` and `resetRateLimitStore()` in `beforeEach` for isolation.
- Prefer route-handler level tests (`import { GET/POST/... } from route`) for behavior coverage.
- Assert both status code and structured response shape (`success`, `error.code`, `meta.requestId`).
````

## File: drizzle.config.ts
````typescript
import { defineConfig } from 'drizzle-kit';

const databaseUrl = process.env.DATABASE_URL;

if (!databaseUrl) {
  throw new Error('DATABASE_URL is required for Drizzle commands');
}

export default defineConfig({
  schema: './lib/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: databaseUrl,
  },
  strict: true,
  verbose: true,
});
````

## File: drizzle/0000_lush_prima.sql
````sql
CREATE TYPE "public"."audit_severity" AS ENUM('info', 'warn', 'error');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('user', 'admin', 'superadmin');--> statement-breakpoint
CREATE TYPE "public"."user_status" AS ENUM('active', 'inactive', 'suspended');--> statement-breakpoint
CREATE TABLE "audit_logs" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text,
	"actor_user_id" text,
	"event_type" text NOT NULL,
	"severity" "audit_severity" DEFAULT 'info' NOT NULL,
	"request_id" text,
	"ip_address" text,
	"user_agent" text,
	"metadata" jsonb DEFAULT 'null'::jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"family_id" text NOT NULL,
	"parent_session_id" text,
	"refresh_token_hash" text NOT NULL,
	"refresh_token_jti" text NOT NULL,
	"ip_address" text,
	"user_agent" text,
	"replaced_by_session_id" text,
	"revoked_at" timestamp with time zone,
	"reuse_detected_at" timestamp with time zone,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" text PRIMARY KEY NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"password_hash" text NOT NULL,
	"role" "user_role" DEFAULT 'user' NOT NULL,
	"status" "user_status" DEFAULT 'active' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_logs" ADD CONSTRAINT "audit_logs_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_logs_user_created_at_idx" ON "audit_logs" USING btree ("user_id","created_at");--> statement-breakpoint
CREATE INDEX "audit_logs_actor_created_at_idx" ON "audit_logs" USING btree ("actor_user_id","created_at");--> statement-breakpoint
CREATE INDEX "sessions_user_revoked_idx" ON "sessions" USING btree ("user_id","revoked_at");--> statement-breakpoint
CREATE INDEX "sessions_expires_at_idx" ON "sessions" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "sessions_refresh_token_jti_unique_idx" ON "sessions" USING btree ("refresh_token_jti");--> statement-breakpoint
CREATE INDEX "sessions_family_idx" ON "sessions" USING btree ("family_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_unique_idx" ON "users" USING btree ("email");
````

## File: drizzle/meta/_journal.json
````json
{
  "version": "7",
  "dialect": "postgresql",
  "entries": [
    {
      "idx": 0,
      "version": "7",
      "when": 1772566094509,
      "tag": "0000_lush_prima",
      "breakpoints": true
    }
  ]
}
````

## File: drizzle/meta/0000_snapshot.json
````json
{
  "id": "0aed0ae8-605b-4db0-9374-15e5769d8645",
  "prevId": "00000000-0000-0000-0000-000000000000",
  "version": "7",
  "dialect": "postgresql",
  "tables": {
    "public.audit_logs": {
      "name": "audit_logs",
      "schema": "",
      "columns": {
        "id": {
          "name": "id",
          "type": "text",
          "primaryKey": true,
          "notNull": true
        },
        "user_id": {
          "name": "user_id",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "actor_user_id": {
          "name": "actor_user_id",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "event_type": {
          "name": "event_type",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "severity": {
          "name": "severity",
          "type": "audit_severity",
          "typeSchema": "public",
          "primaryKey": false,
          "notNull": true,
          "default": "'info'"
        },
        "request_id": {
          "name": "request_id",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "ip_address": {
          "name": "ip_address",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "user_agent": {
          "name": "user_agent",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "metadata": {
          "name": "metadata",
          "type": "jsonb",
          "primaryKey": false,
          "notNull": false,
          "default": "'null'::jsonb"
        },
        "created_at": {
          "name": "created_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": true,
          "default": "now()"
        }
      },
      "indexes": {
        "audit_logs_user_created_at_idx": {
          "name": "audit_logs_user_created_at_idx",
          "columns": [
            {
              "expression": "user_id",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            },
            {
              "expression": "created_at",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": false,
          "concurrently": false,
          "method": "btree",
          "with": {}
        },
        "audit_logs_actor_created_at_idx": {
          "name": "audit_logs_actor_created_at_idx",
          "columns": [
            {
              "expression": "actor_user_id",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            },
            {
              "expression": "created_at",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": false,
          "concurrently": false,
          "method": "btree",
          "with": {}
        }
      },
      "foreignKeys": {
        "audit_logs_user_id_users_id_fk": {
          "name": "audit_logs_user_id_users_id_fk",
          "tableFrom": "audit_logs",
          "tableTo": "users",
          "columnsFrom": [
            "user_id"
          ],
          "columnsTo": [
            "id"
          ],
          "onDelete": "set null",
          "onUpdate": "no action"
        },
        "audit_logs_actor_user_id_users_id_fk": {
          "name": "audit_logs_actor_user_id_users_id_fk",
          "tableFrom": "audit_logs",
          "tableTo": "users",
          "columnsFrom": [
            "actor_user_id"
          ],
          "columnsTo": [
            "id"
          ],
          "onDelete": "set null",
          "onUpdate": "no action"
        }
      },
      "compositePrimaryKeys": {},
      "uniqueConstraints": {},
      "policies": {},
      "checkConstraints": {},
      "isRLSEnabled": false
    },
    "public.sessions": {
      "name": "sessions",
      "schema": "",
      "columns": {
        "id": {
          "name": "id",
          "type": "text",
          "primaryKey": true,
          "notNull": true
        },
        "user_id": {
          "name": "user_id",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "family_id": {
          "name": "family_id",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "parent_session_id": {
          "name": "parent_session_id",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "refresh_token_hash": {
          "name": "refresh_token_hash",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "refresh_token_jti": {
          "name": "refresh_token_jti",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "ip_address": {
          "name": "ip_address",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "user_agent": {
          "name": "user_agent",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "replaced_by_session_id": {
          "name": "replaced_by_session_id",
          "type": "text",
          "primaryKey": false,
          "notNull": false
        },
        "revoked_at": {
          "name": "revoked_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": false
        },
        "reuse_detected_at": {
          "name": "reuse_detected_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": false
        },
        "expires_at": {
          "name": "expires_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": true
        },
        "created_at": {
          "name": "created_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": true,
          "default": "now()"
        },
        "updated_at": {
          "name": "updated_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": true,
          "default": "now()"
        }
      },
      "indexes": {
        "sessions_user_revoked_idx": {
          "name": "sessions_user_revoked_idx",
          "columns": [
            {
              "expression": "user_id",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            },
            {
              "expression": "revoked_at",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": false,
          "concurrently": false,
          "method": "btree",
          "with": {}
        },
        "sessions_expires_at_idx": {
          "name": "sessions_expires_at_idx",
          "columns": [
            {
              "expression": "expires_at",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": false,
          "concurrently": false,
          "method": "btree",
          "with": {}
        },
        "sessions_refresh_token_jti_unique_idx": {
          "name": "sessions_refresh_token_jti_unique_idx",
          "columns": [
            {
              "expression": "refresh_token_jti",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": true,
          "concurrently": false,
          "method": "btree",
          "with": {}
        },
        "sessions_family_idx": {
          "name": "sessions_family_idx",
          "columns": [
            {
              "expression": "family_id",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": false,
          "concurrently": false,
          "method": "btree",
          "with": {}
        }
      },
      "foreignKeys": {
        "sessions_user_id_users_id_fk": {
          "name": "sessions_user_id_users_id_fk",
          "tableFrom": "sessions",
          "tableTo": "users",
          "columnsFrom": [
            "user_id"
          ],
          "columnsTo": [
            "id"
          ],
          "onDelete": "cascade",
          "onUpdate": "no action"
        }
      },
      "compositePrimaryKeys": {},
      "uniqueConstraints": {},
      "policies": {},
      "checkConstraints": {},
      "isRLSEnabled": false
    },
    "public.users": {
      "name": "users",
      "schema": "",
      "columns": {
        "id": {
          "name": "id",
          "type": "text",
          "primaryKey": true,
          "notNull": true
        },
        "email": {
          "name": "email",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "name": {
          "name": "name",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "password_hash": {
          "name": "password_hash",
          "type": "text",
          "primaryKey": false,
          "notNull": true
        },
        "role": {
          "name": "role",
          "type": "user_role",
          "typeSchema": "public",
          "primaryKey": false,
          "notNull": true,
          "default": "'user'"
        },
        "status": {
          "name": "status",
          "type": "user_status",
          "typeSchema": "public",
          "primaryKey": false,
          "notNull": true,
          "default": "'active'"
        },
        "created_at": {
          "name": "created_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": true,
          "default": "now()"
        },
        "updated_at": {
          "name": "updated_at",
          "type": "timestamp with time zone",
          "primaryKey": false,
          "notNull": true,
          "default": "now()"
        }
      },
      "indexes": {
        "users_email_unique_idx": {
          "name": "users_email_unique_idx",
          "columns": [
            {
              "expression": "email",
              "isExpression": false,
              "asc": true,
              "nulls": "last"
            }
          ],
          "isUnique": true,
          "concurrently": false,
          "method": "btree",
          "with": {}
        }
      },
      "foreignKeys": {},
      "compositePrimaryKeys": {},
      "uniqueConstraints": {},
      "policies": {},
      "checkConstraints": {},
      "isRLSEnabled": false
    }
  },
  "enums": {
    "public.audit_severity": {
      "name": "audit_severity",
      "schema": "public",
      "values": [
        "info",
        "warn",
        "error"
      ]
    },
    "public.user_role": {
      "name": "user_role",
      "schema": "public",
      "values": [
        "user",
        "admin",
        "superadmin"
      ]
    },
    "public.user_status": {
      "name": "user_status",
      "schema": "public",
      "values": [
        "active",
        "inactive",
        "suspended"
      ]
    }
  },
  "schemas": {},
  "sequences": {},
  "roles": {},
  "policies": {},
  "views": {},
  "_meta": {
    "columns": {},
    "schemas": {},
    "tables": {}
  }
}
````

## File: lib/auth/jwt.ts
````typescript
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
````

## File: lib/auth/password.ts
````typescript
import bcryptjs from 'bcryptjs';

export async function hashPassword(password: string): Promise<string> {
  const salt = await bcryptjs.genSalt(10);
  return bcryptjs.hash(password, salt);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcryptjs.compare(password, hash);
}
````

## File: lib/auth/session-security.ts
````typescript
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
````

## File: lib/auth/session-service.ts
````typescript
import { type JWTPayload } from 'jose';
import { env } from '@/lib/config/env';
import { db, type DatabaseUser, type SessionRecord } from '@/lib/db/client';
import { signToken, verifyToken } from '@/lib/auth/jwt';
import { durationToMs, durationToSeconds } from '@/lib/utils/duration';
import { AuthenticationError } from '@/lib/utils/errors';
import { generateTokenId, hashRefreshToken, safeEqualHash } from '@/lib/auth/session-security';
import { withTrace } from '@/lib/observability/monitoring';

interface SessionContext {
  ipAddress?: string;
  userAgent?: string;
  requestId?: string;
}

interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  refreshExpiresIn: number;
  sessionId: string;
}

interface RefreshTokenClaims {
  sub: string;
  sid: string;
  jti: string;
  type: 'refresh';
}

function buildAccessTokenPayload(user: DatabaseUser, sessionId: string) {
  return {
    sub: user.id,
    email: user.email,
    role: user.role,
    status: user.status,
    type: 'access',
    sid: sessionId,
  };
}

function parseRefreshClaims(payload: JWTPayload): RefreshTokenClaims {
  if (
    payload.type !== 'refresh' ||
    typeof payload.sub !== 'string' ||
    typeof payload.sid !== 'string' ||
    typeof payload.jti !== 'string'
  ) {
    throw new AuthenticationError('Invalid refresh token');
  }

  return {
    sub: payload.sub,
    sid: payload.sid,
    jti: payload.jti,
    type: 'refresh',
  };
}

async function buildSessionTokens(
  user: DatabaseUser,
  sessionId: string,
  refreshJti: string,
  familyId: string,
  context: SessionContext,
  parentSessionId?: string | null
): Promise<SessionTokens> {
  const refreshToken = await signToken(
    {
      sub: user.id,
      type: 'refresh',
      sid: sessionId,
      jti: refreshJti,
    },
    env.JWT_REFRESH_EXPIRY
  );

  const refreshHash = hashRefreshToken(refreshToken);
  const refreshExpiresAt = new Date(Date.now() + durationToMs(env.JWT_REFRESH_EXPIRY));

  await withTrace('auth.session.create', () =>
    db.createSession({
      id: sessionId,
      userId: user.id,
      familyId,
      parentSessionId: parentSessionId ?? null,
      refreshTokenHash: refreshHash,
      refreshTokenJti: refreshJti,
      ipAddress: context.ipAddress ?? null,
      userAgent: context.userAgent ?? null,
      expiresAt: refreshExpiresAt,
    })
  );

  const accessToken = await signToken(buildAccessTokenPayload(user, sessionId), env.JWT_EXPIRY);

  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    expiresIn: durationToSeconds(env.JWT_EXPIRY),
    refreshExpiresIn: durationToSeconds(env.JWT_REFRESH_EXPIRY),
    sessionId,
  };
}

export async function createSessionTokensForUser(user: DatabaseUser, context: SessionContext): Promise<SessionTokens> {
  const sessionId = generateTokenId();
  const refreshJti = generateTokenId();
  return buildSessionTokens(user, sessionId, refreshJti, sessionId, context);
}

async function revokeFamilyForReuse(sessionId: string, familyId: string, context: SessionContext) {
  await db.markSessionReuseDetected(sessionId);
  await db.revokeSessionFamily(familyId);
  await db.createAuditLog({
    eventType: 'auth.refresh_reuse_detected',
    severity: 'warn',
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: { sessionId, familyId },
  });
}

export async function rotateSessionTokens(refreshToken: string, context: SessionContext): Promise<SessionTokens> {
  const claims = parseRefreshClaims(await verifyToken(refreshToken));
  const session = await withTrace('auth.session.findById', () => db.findSessionById(claims.sid));

  if (!session || session.userId !== claims.sub) {
    throw new AuthenticationError('Invalid refresh token');
  }

  if (session.revokedAt || session.replacedBySessionId || session.reuseDetectedAt) {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  if (session.expiresAt.getTime() <= Date.now()) {
    await db.revokeSession(session.id);
    throw new AuthenticationError('Refresh token expired');
  }

  if (session.refreshTokenJti !== claims.jti) {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  const providedHash = hashRefreshToken(refreshToken);
  if (!safeEqualHash(session.refreshTokenHash, providedHash)) {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  const user = await withTrace('auth.user.findById', () => db.findUserById(session.userId));
  if (!user || user.status !== 'active') {
    await db.revokeSessionFamily(session.familyId);
    throw new AuthenticationError('User account is not active');
  }

  const nextSessionId = generateTokenId();
  const nextJti = generateTokenId();
  const newRefreshToken = await signToken(
    {
      sub: user.id,
      type: 'refresh',
      sid: nextSessionId,
      jti: nextJti,
    },
    env.JWT_REFRESH_EXPIRY
  );

  const nextRefreshHash = hashRefreshToken(newRefreshToken);
  let rotatedSession: SessionRecord;
  try {
    rotatedSession = await withTrace('auth.session.rotate', () =>
      db.rotateSession({
        currentSessionId: session.id,
        replacement: {
          id: nextSessionId,
          userId: user.id,
          familyId: session.familyId,
          parentSessionId: session.id,
          refreshTokenHash: nextRefreshHash,
          refreshTokenJti: nextJti,
          ipAddress: context.ipAddress ?? null,
          userAgent: context.userAgent ?? null,
          expiresAt: new Date(Date.now() + durationToMs(env.JWT_REFRESH_EXPIRY)),
        },
      })
    );
  } catch {
    await revokeFamilyForReuse(session.id, session.familyId, context);
    throw new AuthenticationError('Refresh token reuse detected. Please sign in again.');
  }

  const accessToken = await signToken(buildAccessTokenPayload(user, rotatedSession.id), env.JWT_EXPIRY);

  await db.createAuditLog({
    userId: user.id,
    actorUserId: user.id,
    eventType: 'auth.refresh_rotated',
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: {
      previousSessionId: session.id,
      newSessionId: rotatedSession.id,
    },
  });

  return {
    accessToken,
    refreshToken: newRefreshToken,
    tokenType: 'Bearer',
    expiresIn: durationToSeconds(env.JWT_EXPIRY),
    refreshExpiresIn: durationToSeconds(env.JWT_REFRESH_EXPIRY),
    sessionId: rotatedSession.id,
  };
}

export async function revokeSessionByRefreshToken(refreshToken: string, context: SessionContext): Promise<void> {
  const claims = parseRefreshClaims(await verifyToken(refreshToken));
  const session = await withTrace('auth.session.findById', () => db.findSessionById(claims.sid));
  if (!session) {
    return;
  }

  if (session.userId !== claims.sub) {
    throw new AuthenticationError('Invalid refresh token');
  }

  await db.revokeSession(session.id);
  await db.createAuditLog({
    userId: session.userId,
    actorUserId: session.userId,
    eventType: 'auth.logout',
    requestId: context.requestId ?? null,
    ipAddress: context.ipAddress ?? null,
    userAgent: context.userAgent ?? null,
    metadata: { sessionId: session.id },
  });
}
````

## File: lib/config/env.ts
````typescript
import { z } from 'zod';

const baseEnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  VERCEL_ENV: z.string().default('development'),
  JWT_SECRET: z.string().optional(),
  JWT_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),
  REFRESH_TOKEN_PEPPER: z.string().optional(),
  DATABASE_URL: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  UPSTASH_REDIS_REST_URL: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  UPSTASH_REDIS_REST_TOKEN: z
    .union([z.string().min(1), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  RATE_LIMIT_ENABLED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((value) => value === 'true'),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().positive().default(3_600_000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().positive().default(100),
  ALLOW_IN_MEMORY_SERVICES: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  ALLOW_IN_MEMORY_DB: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  ALLOW_IN_MEMORY_RATE_LIMIT: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  SENTRY_DSN: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  OTEL_EXPORTER_OTLP_ENDPOINT: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  BUILD_VERIFY: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? false : value === 'true')),
});

const parsed = baseEnvSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('[env] Invalid environment variables:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

const data = parsed.data;
const isLikelyTestRuntime = Boolean(process.env.VITEST) || process.argv.some((arg) => arg.toLowerCase().includes('vitest'));
const isTest = data.NODE_ENV === 'test' || isLikelyTestRuntime;
const isProduction = data.NODE_ENV === 'production' || data.VERCEL_ENV === 'production';
const allowInMemoryServices = data.ALLOW_IN_MEMORY_SERVICES ?? (isTest || data.NODE_ENV === 'development');
const allowInMemoryDb = data.ALLOW_IN_MEMORY_DB ?? allowInMemoryServices;
const allowInMemoryRateLimit = data.ALLOW_IN_MEMORY_RATE_LIMIT ?? allowInMemoryServices;
const isBuildVerify = data.BUILD_VERIFY;
const resolvedJwtSecret = data.JWT_SECRET ?? (isTest ? 'test-jwt-secret-12345678901234567890' : undefined);
const resolvedRefreshPepper = data.REFRESH_TOKEN_PEPPER ?? (isTest ? 'test-refresh-pepper-123456' : undefined);

const validationErrors: string[] = [];

if (!resolvedJwtSecret || resolvedJwtSecret.length < 32) {
  validationErrors.push('JWT_SECRET must be at least 32 characters');
}

if (!resolvedRefreshPepper || resolvedRefreshPepper.length < 16) {
  validationErrors.push('REFRESH_TOKEN_PEPPER must be at least 16 characters');
}

if (!data.DATABASE_URL && !allowInMemoryDb) {
  validationErrors.push('DATABASE_URL is required unless ALLOW_IN_MEMORY_DB=true');
}

if ((!data.UPSTASH_REDIS_REST_URL || !data.UPSTASH_REDIS_REST_TOKEN) && !allowInMemoryRateLimit) {
  validationErrors.push('UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required unless ALLOW_IN_MEMORY_RATE_LIMIT=true');
}

if (isProduction && !isBuildVerify && (allowInMemoryServices || allowInMemoryDb || allowInMemoryRateLimit)) {
  validationErrors.push('ALLOW_IN_MEMORY_* flags cannot be true in production');
}

if (validationErrors.length > 0) {
  console.error('[env] Invalid environment variables:');
  for (const error of validationErrors) {
    console.error(` - ${error}`);
  }
  process.exit(1);
}

export const env = {
  ...data,
  JWT_SECRET: resolvedJwtSecret!,
  REFRESH_TOKEN_PEPPER: resolvedRefreshPepper!,
  ALLOW_IN_MEMORY_SERVICES: allowInMemoryServices,
  ALLOW_IN_MEMORY_DB: allowInMemoryDb,
  ALLOW_IN_MEMORY_RATE_LIMIT: allowInMemoryRateLimit,
};

export function isProductionEnvironment() {
  return isProduction;
}
````

## File: lib/db/client.ts
````typescript
import crypto from 'crypto';
import { and, count, desc, eq, ilike, isNull, or } from 'drizzle-orm';
import { env } from '@/lib/config/env';
import { checkDatabaseHealth, getDrizzleClient } from '@/lib/db/connection';
import { auditLogs, sessions, users, type AuditLogRow, type SessionRow, type UserRow } from '@/lib/db/schema';
import { logger } from '@/lib/utils/logger';
import { type User } from '@/lib/types';

export interface DatabaseUser extends User {
  passwordHash: string;
}

export interface SessionRecord {
  id: string;
  userId: string;
  familyId: string;
  parentSessionId: string | null;
  refreshTokenHash: string;
  refreshTokenJti: string;
  ipAddress: string | null;
  userAgent: string | null;
  replacedBySessionId: string | null;
  revokedAt: Date | null;
  reuseDetectedAt: Date | null;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface CreateSessionInput {
  id: string;
  userId: string;
  familyId: string;
  parentSessionId?: string | null;
  refreshTokenHash: string;
  refreshTokenJti: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  expiresAt: Date;
}

export interface RotateSessionInput {
  currentSessionId: string;
  replacement: CreateSessionInput;
}

export interface AuditLogInput {
  userId?: string | null;
  actorUserId?: string | null;
  eventType: string;
  severity?: 'info' | 'warn' | 'error';
  requestId?: string | null;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown> | null;
}

interface UserListResult {
  users: DatabaseUser[];
  total: number;
}

interface DatabaseClient {
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
  findUserByEmail(email: string): Promise<DatabaseUser | null>;
  findUserById(id: string): Promise<DatabaseUser | null>;
  createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<DatabaseUser>;
  updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null>;
  deleteUser(id: string): Promise<boolean>;
  getAllUsers(page?: number, limit?: number): Promise<UserListResult>;
  searchUsers(query: string, page?: number, limit?: number): Promise<UserListResult>;
  createSession(session: CreateSessionInput): Promise<SessionRecord>;
  findSessionById(sessionId: string): Promise<SessionRecord | null>;
  rotateSession(input: RotateSessionInput): Promise<SessionRecord>;
  revokeSession(sessionId: string): Promise<boolean>;
  revokeSessionFamily(familyId: string): Promise<number>;
  markSessionReuseDetected(sessionId: string): Promise<void>;
  createAuditLog(log: AuditLogInput): Promise<void>;
  reset(): Promise<void>;
}

function mapUserRow(row: UserRow): DatabaseUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    passwordHash: row.passwordHash,
    role: row.role,
    status: row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapSessionRow(row: SessionRow): SessionRecord {
  return {
    id: row.id,
    userId: row.userId,
    familyId: row.familyId,
    parentSessionId: row.parentSessionId,
    refreshTokenHash: row.refreshTokenHash,
    refreshTokenJti: row.refreshTokenJti,
    ipAddress: row.ipAddress,
    userAgent: row.userAgent,
    replacedBySessionId: row.replacedBySessionId,
    revokedAt: row.revokedAt,
    reuseDetectedAt: row.reuseDetectedAt,
    expiresAt: row.expiresAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function sanitizeUserUpdate(
  updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>
): Partial<Omit<DatabaseUser, 'id' | 'createdAt'>> {
  const sanitized: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>> = {};
  for (const [key, value] of Object.entries(updates)) {
    if (value !== undefined) {
      (sanitized as Record<string, unknown>)[key] = key === 'email' ? normalizeEmail(String(value)) : value;
    }
  }
  return sanitized;
}

class PostgresDatabase implements DatabaseClient {
  async initialize(): Promise<void> {
    await checkDatabaseHealth();
  }

  async healthCheck(): Promise<boolean> {
    return checkDatabaseHealth();
  }

  async findUserByEmail(email: string): Promise<DatabaseUser | null> {
    const drizzle = getDrizzleClient();
    const [result] = await drizzle.select().from(users).where(eq(users.email, normalizeEmail(email))).limit(1);
    return result ? mapUserRow(result) : null;
  }

  async findUserById(id: string): Promise<DatabaseUser | null> {
    const drizzle = getDrizzleClient();
    const [result] = await drizzle.select().from(users).where(eq(users.id, id)).limit(1);
    return result ? mapUserRow(result) : null;
  }

  async createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<DatabaseUser> {
    const drizzle = getDrizzleClient();
    const now = new Date();
    const id = crypto.randomUUID();
    const [inserted] = await drizzle
      .insert(users)
      .values({
        id,
        email: normalizeEmail(user.email),
        name: user.name,
        passwordHash: user.passwordHash,
        role: user.role,
        status: user.status,
        createdAt: now,
        updatedAt: now,
      })
      .returning();

    return mapUserRow(inserted);
  }

  async updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null> {
    const drizzle = getDrizzleClient();
    const sanitized = sanitizeUserUpdate(updates);
    if (Object.keys(sanitized).length === 0) {
      return this.findUserById(id);
    }

    const [updated] = await drizzle
      .update(users)
      .set({
        ...sanitized,
        updatedAt: new Date(),
      })
      .where(eq(users.id, id))
      .returning();

    return updated ? mapUserRow(updated) : null;
  }

  async deleteUser(id: string): Promise<boolean> {
    const drizzle = getDrizzleClient();
    const [deleted] = await drizzle.delete(users).where(eq(users.id, id)).returning({ id: users.id });
    return Boolean(deleted?.id);
  }

  async getAllUsers(page: number = 1, limit: number = 20): Promise<UserListResult> {
    const drizzle = getDrizzleClient();
    const offset = (page - 1) * limit;
    const [totalResult, pageResults] = await Promise.all([
      drizzle.select({ total: count(users.id) }).from(users),
      drizzle.select().from(users).orderBy(desc(users.createdAt)).limit(limit).offset(offset),
    ]);

    return {
      users: pageResults.map(mapUserRow),
      total: Number(totalResult[0]?.total ?? 0),
    };
  }

  async searchUsers(query: string, page: number = 1, limit: number = 20): Promise<UserListResult> {
    const drizzle = getDrizzleClient();
    const offset = (page - 1) * limit;
    const condition = or(ilike(users.email, `%${query}%`), ilike(users.name, `%${query}%`));

    const [totalResult, pageResults] = await Promise.all([
      drizzle.select({ total: count(users.id) }).from(users).where(condition),
      drizzle.select().from(users).where(condition).orderBy(desc(users.createdAt)).limit(limit).offset(offset),
    ]);

    return {
      users: pageResults.map(mapUserRow),
      total: Number(totalResult[0]?.total ?? 0),
    };
  }

  async createSession(session: CreateSessionInput): Promise<SessionRecord> {
    const drizzle = getDrizzleClient();
    const now = new Date();
    const [inserted] = await drizzle
      .insert(sessions)
      .values({
        id: session.id,
        userId: session.userId,
        familyId: session.familyId,
        parentSessionId: session.parentSessionId ?? null,
        refreshTokenHash: session.refreshTokenHash,
        refreshTokenJti: session.refreshTokenJti,
        ipAddress: session.ipAddress ?? null,
        userAgent: session.userAgent ?? null,
        expiresAt: session.expiresAt,
        createdAt: now,
        updatedAt: now,
      })
      .returning();

    return mapSessionRow(inserted);
  }

  async findSessionById(sessionId: string): Promise<SessionRecord | null> {
    const drizzle = getDrizzleClient();
    const [session] = await drizzle.select().from(sessions).where(eq(sessions.id, sessionId)).limit(1);
    return session ? mapSessionRow(session) : null;
  }

  async rotateSession(input: RotateSessionInput): Promise<SessionRecord> {
    const drizzle = getDrizzleClient();
    const now = new Date();

    return drizzle.transaction(async (tx) => {
      const currentUpdate = await tx
        .update(sessions)
        .set({
          revokedAt: now,
          replacedBySessionId: input.replacement.id,
          updatedAt: now,
        })
        .where(and(eq(sessions.id, input.currentSessionId), isNull(sessions.revokedAt)))
        .returning({ id: sessions.id });

      if (currentUpdate.length === 0) {
        throw new Error('Session was already rotated or revoked');
      }

      const [newSession] = await tx
        .insert(sessions)
        .values({
          id: input.replacement.id,
          userId: input.replacement.userId,
          familyId: input.replacement.familyId,
          parentSessionId: input.replacement.parentSessionId ?? null,
          refreshTokenHash: input.replacement.refreshTokenHash,
          refreshTokenJti: input.replacement.refreshTokenJti,
          ipAddress: input.replacement.ipAddress ?? null,
          userAgent: input.replacement.userAgent ?? null,
          expiresAt: input.replacement.expiresAt,
          createdAt: now,
          updatedAt: now,
        })
        .returning();

      return mapSessionRow(newSession);
    });
  }

  async revokeSession(sessionId: string): Promise<boolean> {
    const drizzle = getDrizzleClient();
    const [revoked] = await drizzle
      .update(sessions)
      .set({ revokedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(sessions.id, sessionId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });

    return Boolean(revoked?.id);
  }

  async revokeSessionFamily(familyId: string): Promise<number> {
    const drizzle = getDrizzleClient();
    const revoked = await drizzle
      .update(sessions)
      .set({ revokedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(sessions.familyId, familyId), isNull(sessions.revokedAt)))
      .returning({ id: sessions.id });

    return revoked.length;
  }

  async markSessionReuseDetected(sessionId: string): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle
      .update(sessions)
      .set({ reuseDetectedAt: new Date(), updatedAt: new Date() })
      .where(eq(sessions.id, sessionId));
  }

  async createAuditLog(log: AuditLogInput): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle.insert(auditLogs).values({
      id: crypto.randomUUID(),
      userId: log.userId ?? null,
      actorUserId: log.actorUserId ?? null,
      eventType: log.eventType,
      severity: log.severity ?? 'info',
      requestId: log.requestId ?? null,
      ipAddress: log.ipAddress ?? null,
      userAgent: log.userAgent ?? null,
      metadata: log.metadata ?? null,
      createdAt: new Date(),
    });
  }

  async reset(): Promise<void> {
    if (env.NODE_ENV !== 'test') {
      return;
    }

    const drizzle = getDrizzleClient();
    await drizzle.delete(auditLogs);
    await drizzle.delete(sessions);
    await drizzle.delete(users);
  }
}

class InMemoryDatabase implements DatabaseClient {
  private users = new Map<string, DatabaseUser>();
  private usersByEmail = new Map<string, string>();
  private sessions = new Map<string, SessionRecord>();
  private auditTrail: AuditLogRow[] = [];

  async initialize(): Promise<void> {}

  async healthCheck(): Promise<boolean> {
    return true;
  }

  async findUserByEmail(email: string): Promise<DatabaseUser | null> {
    const id = this.usersByEmail.get(normalizeEmail(email));
    return id ? (this.users.get(id) ?? null) : null;
  }

  async findUserById(id: string): Promise<DatabaseUser | null> {
    return this.users.get(id) ?? null;
  }

  async createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt'>): Promise<DatabaseUser> {
    const now = new Date();
    const created: DatabaseUser = {
      ...user,
      id: crypto.randomUUID(),
      email: normalizeEmail(user.email),
      createdAt: now,
      updatedAt: now,
    };
    this.users.set(created.id, created);
    this.usersByEmail.set(created.email, created.id);
    return created;
  }

  async updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null> {
    const user = this.users.get(id);
    if (!user) {
      return null;
    }

    const updated: DatabaseUser = {
      ...user,
      ...sanitizeUserUpdate(updates),
      updatedAt: new Date(),
    };

    this.users.set(id, updated);
    this.usersByEmail.set(updated.email, updated.id);
    return updated;
  }

  async deleteUser(id: string): Promise<boolean> {
    const user = this.users.get(id);
    if (!user) {
      return false;
    }
    this.users.delete(id);
    this.usersByEmail.delete(user.email);
    return true;
  }

  async getAllUsers(page: number = 1, limit: number = 20): Promise<UserListResult> {
    const allUsers = Array.from(this.users.values()).sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const start = (page - 1) * limit;
    return { users: allUsers.slice(start, start + limit), total: allUsers.length };
  }

  async searchUsers(query: string, page: number = 1, limit: number = 20): Promise<UserListResult> {
    const normalizedQuery = query.toLowerCase();
    const filtered = Array.from(this.users.values())
      .filter((user) => user.email.includes(normalizedQuery) || user.name.toLowerCase().includes(normalizedQuery))
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
    const start = (page - 1) * limit;
    return { users: filtered.slice(start, start + limit), total: filtered.length };
  }

  async createSession(session: CreateSessionInput): Promise<SessionRecord> {
    const now = new Date();
    const created: SessionRecord = {
      id: session.id,
      userId: session.userId,
      familyId: session.familyId,
      parentSessionId: session.parentSessionId ?? null,
      refreshTokenHash: session.refreshTokenHash,
      refreshTokenJti: session.refreshTokenJti,
      ipAddress: session.ipAddress ?? null,
      userAgent: session.userAgent ?? null,
      replacedBySessionId: null,
      revokedAt: null,
      reuseDetectedAt: null,
      expiresAt: session.expiresAt,
      createdAt: now,
      updatedAt: now,
    };
    this.sessions.set(created.id, created);
    return created;
  }

  async findSessionById(sessionId: string): Promise<SessionRecord | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async rotateSession(input: RotateSessionInput): Promise<SessionRecord> {
    const current = this.sessions.get(input.currentSessionId);
    if (current && !current.revokedAt) {
      current.revokedAt = new Date();
      current.replacedBySessionId = input.replacement.id;
      current.updatedAt = new Date();
      this.sessions.set(current.id, current);
    }

    return this.createSession(input.replacement);
  }

  async revokeSession(sessionId: string): Promise<boolean> {
    const session = this.sessions.get(sessionId);
    if (!session || session.revokedAt) {
      return false;
    }

    session.revokedAt = new Date();
    session.updatedAt = new Date();
    this.sessions.set(sessionId, session);
    return true;
  }

  async revokeSessionFamily(familyId: string): Promise<number> {
    let revoked = 0;
    for (const session of this.sessions.values()) {
      if (session.familyId === familyId && !session.revokedAt) {
        session.revokedAt = new Date();
        session.updatedAt = new Date();
        this.sessions.set(session.id, session);
        revoked++;
      }
    }
    return revoked;
  }

  async markSessionReuseDetected(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) {
      return;
    }
    session.reuseDetectedAt = new Date();
    session.updatedAt = new Date();
    this.sessions.set(sessionId, session);
  }

  async createAuditLog(log: AuditLogInput): Promise<void> {
    this.auditTrail.push({
      id: crypto.randomUUID(),
      userId: log.userId ?? null,
      actorUserId: log.actorUserId ?? null,
      eventType: log.eventType,
      severity: log.severity ?? 'info',
      requestId: log.requestId ?? null,
      ipAddress: log.ipAddress ?? null,
      userAgent: log.userAgent ?? null,
      metadata: log.metadata ?? null,
      createdAt: new Date(),
    });
  }

  async reset(): Promise<void> {
    this.users.clear();
    this.usersByEmail.clear();
    this.sessions.clear();
    this.auditTrail = [];
  }
}

const useInMemoryAdapter = env.ALLOW_IN_MEMORY_DB || !env.DATABASE_URL;

if (useInMemoryAdapter) {
  if (env.NODE_ENV === 'test' && !env.BUILD_VERIFY) {
    logger.warn('DATABASE_URL not set in test mode. Using in-memory database adapter for tests.');
  }
}

export const db: DatabaseClient = useInMemoryAdapter ? new InMemoryDatabase() : new PostgresDatabase();

export async function resetMockDatabase() {
  await db.reset();
}

db.initialize().catch((error) => {
  logger.error('Database initialization failed', { error: error instanceof Error ? error.message : String(error) });
});
````

## File: lib/db/connection.ts
````typescript
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { env } from '@/lib/config/env';

let sqlClient: postgres.Sql | null = null;
let drizzleClient: ReturnType<typeof drizzle> | null = null;

function getSslMode(): boolean | 'require' {
  return env.NODE_ENV === 'development' || env.NODE_ENV === 'test' ? false : 'require';
}

export function getSqlClient(): postgres.Sql {
  if (!env.DATABASE_URL) {
    throw new Error('DATABASE_URL is not configured');
  }

  if (!sqlClient) {
    sqlClient = postgres(env.DATABASE_URL, {
      max: 10,
      ssl: getSslMode(),
      prepare: false,
      idle_timeout: 20,
      connect_timeout: 10,
    });
  }

  return sqlClient;
}

export function getDrizzleClient() {
  if (!drizzleClient) {
    drizzleClient = drizzle(getSqlClient());
  }

  return drizzleClient;
}

export async function closeDatabaseConnection() {
  if (sqlClient) {
    await sqlClient.end({ timeout: 1 });
    sqlClient = null;
    drizzleClient = null;
  }
}

export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const client = getSqlClient();
    await client`select 1`;
    return true;
  } catch {
    return false;
  }
}
````

## File: lib/db/schema.ts
````typescript
import { index, jsonb, pgEnum, pgTable, text, timestamp, uniqueIndex } from 'drizzle-orm/pg-core';

export const userRoleEnum = pgEnum('user_role', ['user', 'admin', 'superadmin']);
export const userStatusEnum = pgEnum('user_status', ['active', 'inactive', 'suspended']);
export const auditSeverityEnum = pgEnum('audit_severity', ['info', 'warn', 'error']);

export const users = pgTable(
  'users',
  {
    id: text('id').primaryKey(),
    email: text('email').notNull(),
    name: text('name').notNull(),
    passwordHash: text('password_hash').notNull(),
    role: userRoleEnum('role').notNull().default('user'),
    status: userStatusEnum('status').notNull().default('active'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    emailUniqueIdx: uniqueIndex('users_email_unique_idx').on(table.email),
  })
);

export const sessions = pgTable(
  'sessions',
  {
    id: text('id').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    familyId: text('family_id').notNull(),
    parentSessionId: text('parent_session_id'),
    refreshTokenHash: text('refresh_token_hash').notNull(),
    refreshTokenJti: text('refresh_token_jti').notNull(),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    replacedBySessionId: text('replaced_by_session_id'),
    revokedAt: timestamp('revoked_at', { withTimezone: true }),
    reuseDetectedAt: timestamp('reuse_detected_at', { withTimezone: true }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userRevokedIdx: index('sessions_user_revoked_idx').on(table.userId, table.revokedAt),
    expiresAtIdx: index('sessions_expires_at_idx').on(table.expiresAt),
    jtiUniqueIdx: uniqueIndex('sessions_refresh_token_jti_unique_idx').on(table.refreshTokenJti),
    familyIdx: index('sessions_family_idx').on(table.familyId),
  })
);

export const auditLogs = pgTable(
  'audit_logs',
  {
    id: text('id').primaryKey(),
    userId: text('user_id').references(() => users.id, { onDelete: 'set null' }),
    actorUserId: text('actor_user_id').references(() => users.id, { onDelete: 'set null' }),
    eventType: text('event_type').notNull(),
    severity: auditSeverityEnum('severity').notNull().default('info'),
    requestId: text('request_id'),
    ipAddress: text('ip_address'),
    userAgent: text('user_agent'),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>().default(null),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userCreatedAtIdx: index('audit_logs_user_created_at_idx').on(table.userId, table.createdAt),
    actorCreatedAtIdx: index('audit_logs_actor_created_at_idx').on(table.actorUserId, table.createdAt),
  })
);

export type UserRow = typeof users.$inferSelect;
export type SessionRow = typeof sessions.$inferSelect;
export type AuditLogRow = typeof auditLogs.$inferSelect;
````

## File: lib/middleware/auth.ts
````typescript
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
````

## File: lib/middleware/rate-limit.ts
````typescript
import { Ratelimit } from '@upstash/ratelimit';
import { env } from '@/lib/config/env';
import { getRedisClient } from '@/lib/platform/redis';
import { RateLimitError, ServiceUnavailableError } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';

interface RateLimitPolicy {
  windowMs?: number;
  maxRequests?: number;
  failOpen?: boolean;
}

interface InMemoryRecord {
  count: number;
  resetTime: number;
}

const inMemoryStore = new Map<string, InMemoryRecord>();
const limiterCache = new Map<string, Ratelimit>();

const shouldUseInMemoryLimiter =
  env.ALLOW_IN_MEMORY_RATE_LIMIT || !env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN;

function getWindow(windowMs: number): `${number} s` {
  return `${Math.max(1, Math.floor(windowMs / 1000))} s`;
}

function getLimiter(windowMs: number, maxRequests: number): Ratelimit {
  const key = `${windowMs}:${maxRequests}`;
  const cached = limiterCache.get(key);
  if (cached) {
    return cached;
  }

  const limiter = new Ratelimit({
    redis: getRedisClient(),
    limiter: Ratelimit.fixedWindow(maxRequests, getWindow(windowMs)),
    prefix: 'swissknife',
  });

  limiterCache.set(key, limiter);
  return limiter;
}

function checkRateLimitInMemory(identifier: string, windowMs: number, maxRequests: number) {
  const now = Date.now();
  const existing = inMemoryStore.get(identifier);
  if (!existing || now > existing.resetTime) {
    inMemoryStore.set(identifier, { count: 1, resetTime: now + windowMs });
    return;
  }

  existing.count += 1;
  if (existing.count > maxRequests) {
    throw new RateLimitError(`Rate limit exceeded. Max ${maxRequests} requests per ${Math.round(windowMs / 60000)} minutes`);
  }
}

export async function checkRateLimit(identifier: string, policy: RateLimitPolicy = {}): Promise<void> {
  if (!env.RATE_LIMIT_ENABLED) {
    logger.warn('Rate limiting is disabled. Do not use this setting in production.');
    return;
  }

  const windowMs = policy.windowMs ?? env.RATE_LIMIT_WINDOW_MS;
  const maxRequests = policy.maxRequests ?? env.RATE_LIMIT_MAX_REQUESTS;
  const failOpen = policy.failOpen ?? true;

  if (shouldUseInMemoryLimiter) {
    checkRateLimitInMemory(identifier, windowMs, maxRequests);
    return;
  }

  try {
    const limiter = getLimiter(windowMs, maxRequests);
    const result = await limiter.limit(identifier);
    if (!result.success) {
      throw new RateLimitError(`Rate limit exceeded. Max ${maxRequests} requests per ${Math.round(windowMs / 60000)} minutes`);
    }
  } catch (error) {
    if (error instanceof RateLimitError) {
      throw error;
    }

    logger.error('Rate limiter dependency unavailable', {
      identifier,
      failOpen,
      error: error instanceof Error ? error.message : String(error),
      alertTag: 'rate_limit_dependency_unavailable',
    });

    if (failOpen) {
      return;
    }

    throw new ServiceUnavailableError('Rate limit service unavailable');
  }
}

export function createRateLimitMiddleware(windowMs: number = env.RATE_LIMIT_WINDOW_MS, maxRequests: number = env.RATE_LIMIT_MAX_REQUESTS, failOpen: boolean = true) {
  return async (identifier: string): Promise<void> => {
    await checkRateLimit(identifier, { windowMs, maxRequests, failOpen });
  };
}

export async function resetRateLimitStore() {
  inMemoryStore.clear();
  limiterCache.clear();
}
````

## File: lib/observability/monitoring.ts
````typescript
import { SpanStatusCode, context, trace } from '@opentelemetry/api';
import { env } from '@/lib/config/env';
import { logger } from '@/lib/utils/logger';

type SentryModule = {
  init: (options: { dsn: string; environment: string; tracesSampleRate: number }) => void;
  captureException: (error: unknown, context?: { extra?: Record<string, unknown> }) => void;
};

let sentryModulePromise: Promise<SentryModule | null> | null = null;
let sentryInitialized = false;

async function loadSentryModule(): Promise<SentryModule | null> {
  if (!env.SENTRY_DSN) {
    return null;
  }

  if (!sentryModulePromise) {
    sentryModulePromise = import(/* webpackIgnore: true */ '@sentry/node')
      .then((mod) => mod as unknown as SentryModule)
      .catch((error) => {
        logger.warn('Sentry module could not be loaded', {
          error: error instanceof Error ? error.message : String(error),
        });
        return null;
      });
  }

  return sentryModulePromise;
}

async function initializeSentryIfNeeded() {
  if (sentryInitialized || !env.SENTRY_DSN) {
    return;
  }

  const sentry = await loadSentryModule();
  if (!sentry) {
    return;
  }

  sentry.init({
    dsn: env.SENTRY_DSN,
    environment: env.NODE_ENV,
    tracesSampleRate: 0.1,
  });
  sentryInitialized = true;
}

export function captureException(error: unknown, metadata?: Record<string, unknown>) {
  if (!env.SENTRY_DSN) {
    return;
  }

  void (async () => {
    await initializeSentryIfNeeded();
    const sentry = await loadSentryModule();
    if (!sentry) {
      return;
    }

    sentry.captureException(error, {
      extra: metadata,
    });
  })();
}

export async function withTrace<T>(spanName: string, fn: () => Promise<T>): Promise<T> {
  const tracer = trace.getTracer('swissknife');
  const span = tracer.startSpan(spanName);

  return context.with(trace.setSpan(context.active(), span), async () => {
    try {
      const result = await fn();
      span.setStatus({ code: SpanStatusCode.OK });
      return result;
    } catch (error) {
      span.recordException(error as Error);
      span.setStatus({ code: SpanStatusCode.ERROR, message: error instanceof Error ? error.message : String(error) });
      throw error;
    } finally {
      span.end();
    }
  });
}
````

## File: lib/platform/redis.ts
````typescript
import { Redis } from '@upstash/redis';
import { env } from '@/lib/config/env';

let redisClient: Redis | null = null;

export function getRedisClient(): Redis {
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) {
    throw new Error('Upstash Redis credentials are not configured');
  }

  if (!redisClient) {
    redisClient = new Redis({
      url: env.UPSTASH_REDIS_REST_URL,
      token: env.UPSTASH_REDIS_REST_TOKEN,
    });
  }

  return redisClient;
}

export async function checkRedisHealth(): Promise<boolean> {
  if (env.ALLOW_IN_MEMORY_RATE_LIMIT && (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN)) {
    return true;
  }

  try {
    const redis = getRedisClient();
    await redis.ping();
    return true;
  } catch {
    return false;
  }
}
````

## File: lib/types/index.ts
````typescript
export interface User {
  id: string;
  email: string;
  name: string;
  role: 'user' | 'admin' | 'superadmin';
  status: 'active' | 'inactive' | 'suspended';
  createdAt: Date;
  updatedAt: Date;
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
  meta: {
    timestamp: string;
    requestId: string;
  };
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  meta: {
    timestamp: string;
    requestId: string;
    pagination: {
      page: number;
      limit: number;
      total: number;
      totalPages: number;
    };
  };
}

export interface ErrorDetails {
  code: string;
  message: string;
  status: number;
  details?: Record<string, unknown>;
}
````

## File: lib/utils/duration.ts
````typescript
const DURATION_PATTERN = /^(\d+)(s|m|h|d)$/i;

const UNIT_TO_SECONDS: Record<string, number> = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 60 * 60 * 24,
};

export function durationToSeconds(duration: string): number {
  const match = duration.match(DURATION_PATTERN);
  if (!match) {
    throw new Error(`Invalid duration format: ${duration}. Expected formats like 15m, 7d.`);
  }

  const value = Number(match[1]);
  const unit = match[2].toLowerCase();
  return value * UNIT_TO_SECONDS[unit];
}

export function durationToMs(duration: string): number {
  return durationToSeconds(duration) * 1000;
}
````

## File: lib/utils/errors.ts
````typescript
import { type ErrorDetails } from '@/lib/types';

export class AppError extends Error {
  constructor(
    public code: string,
    public status: number,
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: Record<string, unknown>) {
    super('VALIDATION_ERROR', 400, message, details);
    this.name = 'ValidationError';
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication failed') {
    super('AUTHENTICATION_ERROR', 401, message);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super('AUTHORIZATION_ERROR', 403, message);
    this.name = 'AuthorizationError';
  }
}

export class NotFoundError extends AppError {
  constructor(message: string = 'Resource not found') {
    super('NOT_FOUND', 404, message);
    this.name = 'NotFoundError';
  }
}

export class ConflictError extends AppError {
  constructor(message: string = 'Resource already exists') {
    super('CONFLICT', 409, message);
    this.name = 'ConflictError';
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Too many requests') {
    super('RATE_LIMIT_EXCEEDED', 429, message);
    this.name = 'RateLimitError';
  }
}

export class InternalServerError extends AppError {
  constructor(message: string = 'Internal server error') {
    super('INTERNAL_SERVER_ERROR', 500, message);
    this.name = 'InternalServerError';
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message: string = 'Service unavailable') {
    super('SERVICE_UNAVAILABLE', 503, message);
    this.name = 'ServiceUnavailableError';
  }
}

export function getErrorDetails(error: unknown): ErrorDetails {
  if (error instanceof AppError) {
    return {
      code: error.code,
      message: error.message,
      status: error.status,
      details: error.details,
    };
  }

  if (error instanceof Error) {
    return {
      code: 'INTERNAL_SERVER_ERROR',
      message: error.message,
      status: 500,
    };
  }

  return {
    code: 'INTERNAL_SERVER_ERROR',
    message: 'An unexpected error occurred',
    status: 500,
  };
}
````

## File: lib/utils/logger.ts
````typescript
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  requestId?: string;
  userId?: string;
  endpoint?: string;
  status?: number;
  latencyMs?: number;
}

interface LogEntry {
  level: LogLevel;
  timestamp: string;
  message: string;
  requestId?: string;
  context?: LogContext;
  data?: unknown;
}

const REDACTED = '[REDACTED]';
const SENSITIVE_FIELD_PATTERN = /(password|token|secret|authorization|cookie|pepper|key)/i;

function redactValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(redactValue);
  }

  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).map(([key, nestedValue]) => {
      if (SENSITIVE_FIELD_PATTERN.test(key)) {
        return [key, REDACTED];
      }
      return [key, redactValue(nestedValue)];
    });

    return Object.fromEntries(entries);
  }

  if (typeof value === 'string' && value.length > 2000) {
    return `${value.slice(0, 2000)}...`;
  }

  return value;
}

class Logger {
  private readonly isDevelopment = process.env.NODE_ENV === 'development';

  private write(level: LogLevel, message: string, data?: unknown, requestId?: string, context?: LogContext) {
    const entry: LogEntry = {
      level,
      timestamp: new Date().toISOString(),
      message,
      requestId,
      context,
      data: data === undefined ? undefined : redactValue(data),
    };

    if (this.isDevelopment) {
      const base = `[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}`;
      console.log(base, JSON.stringify({ requestId: entry.requestId, context: entry.context, data: entry.data }));
      return;
    }

    console.log(JSON.stringify(entry));
  }

  debug(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    if (!this.isDevelopment) {
      return;
    }
    this.write('debug', message, data, requestId, context);
  }

  info(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    this.write('info', message, data, requestId, context);
  }

  warn(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    this.write('warn', message, data, requestId, context);
  }

  error(message: string, data?: unknown, requestId?: string, context?: LogContext) {
    this.write('error', message, data, requestId, context);
  }
}

export const logger = new Logger();
````

## File: lib/utils/request.ts
````typescript
import { type NextRequest } from 'next/server';

export function getClientIp(request: NextRequest): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'unknown'
  );
}

export function hasJsonContentType(request: NextRequest): boolean {
  const contentType = request.headers.get('content-type');
  return Boolean(contentType && contentType.toLowerCase().includes('application/json'));
}
````

## File: lib/utils/response.ts
````typescript
import { type ApiResponse, type PaginatedResponse } from '@/lib/types';
import { NextResponse } from 'next/server';
import crypto from 'crypto';

function generateRequestId(): string {
  return crypto.randomUUID();
}

export function successResponse<T>(data: T, status: number = 200, requestId?: string) {
  const resolvedRequestId = requestId ?? generateRequestId();
  const response: ApiResponse<T> = {
    success: true,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: resolvedRequestId,
    },
  };

  return NextResponse.json(response, {
    status,
    headers: {
      'X-Request-Id': resolvedRequestId,
    },
  });
}

export function paginatedResponse<T>(
  data: T[],
  page: number,
  limit: number,
  total: number,
  status: number = 200,
  requestId?: string
) {
  const resolvedRequestId = requestId ?? generateRequestId();
  const totalPages = Math.ceil(total / limit);
  const response: PaginatedResponse<T> = {
    success: true,
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: resolvedRequestId,
      pagination: {
        page,
        limit,
        total,
        totalPages,
      },
    },
  };

  return NextResponse.json(response, {
    status,
    headers: {
      'X-Request-Id': resolvedRequestId,
    },
  });
}

export function errorResponse(
  code: string,
  message: string,
  status: number,
  details?: Record<string, unknown>,
  requestId?: string
) {
  const resolvedRequestId = requestId ?? generateRequestId();
  const response: ApiResponse = {
    success: false,
    error: {
      code,
      message,
      details,
    },
    meta: {
      timestamp: new Date().toISOString(),
      requestId: resolvedRequestId,
    },
  };

  return NextResponse.json(response, {
    status,
    headers: {
      'X-Request-Id': resolvedRequestId,
    },
  });
}
````

## File: lib/validation/schemas.ts
````typescript
import { z } from 'zod';

export const createUserSchema = z.object({
  email: z.string().email('Invalid email address'),
  name: z.string().min(2, 'Name must be at least 2 characters'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

export const updateUserSchema = z.object({
  name: z.string().min(2).optional(),
  role: z.enum(['user', 'admin']).optional(),
  status: z.enum(['active', 'inactive', 'suspended']).optional(),
});

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
});

export const paginationSchema = z.object({
  page: z.coerce.number().min(1).default(1),
  limit: z.coerce.number().min(1).max(100).default(20),
  search: z.string().optional(),
});

export type CreateUserInput = z.infer<typeof createUserSchema>;
export type UpdateUserInput = z.infer<typeof updateUserSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type PaginationInput = z.infer<typeof paginationSchema>;
````

## File: next.config.js
````javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  typescript: {
    tsconfigPath: './tsconfig.json',
  },
  headers: async () => {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-XSS-Protection',
            value: '0',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
        ],
      },
      {
        source: '/api/(.*)',
        headers: [
          {
            key: 'Content-Type',
            value: 'application/json',
          },
        ],
      },
    ];
  },
  redirects: async () => {
    return [];
  },
};

module.exports = nextConfig;
````

## File: postcss.config.js
````javascript
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
````

## File: QUICK_START.md
````markdown
# SwissKnife Quick Start

## 1) Install
```bash
corepack enable
corepack pnpm install
```

## 2) Configure
```bash
cp .env.example .env.local
```

## 3) Run
```bash
corepack pnpm db:migrate
corepack pnpm dev
```

## 4) Verify
```bash
corepack pnpm verify
```

If `JWT_SECRET` is not exported in your shell, `verify` uses a temporary value for the build check only. Runtime startup still requires a real `JWT_SECRET` (32+ chars).
If `REFRESH_TOKEN_PEPPER` is not set, startup fails. Set required values in `.env.local`.

## Local URLs
- Home: `http://localhost:3000`
- API base: `http://localhost:3000/api`

## API Smoke Tests
Register:
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "name": "Test User",
    "password": "TestPassword123!"
  }'
```

Login:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!"
  }'
```

## Core Files
- `app/page.tsx` - minimal starter landing page
- `app/api/auth/register/route.ts` - register endpoint
- `app/api/auth/login/route.ts` - login endpoint
- `app/api/users/route.ts` - list users (admin roles)
- `app/api/users/[id]/route.ts` - user CRUD by id
- `lib/db/client.ts` - Postgres/Drizzle repository adapter
- `lib/middleware/auth.ts` - auth and role checks
- `lib/middleware/rate-limit.ts` - request limiter
- `lib/utils/response.ts` - API response envelope

## Common Commands
```bash
corepack pnpm dev
corepack pnpm type-check
corepack pnpm lint
corepack pnpm test
corepack pnpm build
corepack pnpm verify
```
````

## File: repomix.config.ts
````typescript
import { defineConfig } from 'repomix';

export default defineConfig({
  // Exclude build artifacts and large files
  exclude: [
    '**/node_modules/**',
    '**/.next/**',
    '**/dist/**',
    '**/build/**',
    'tsconfig.tsbuildinfo',
    '*.lock',
    'pnpm-lock.yaml',
    'package-lock.json',
    '.git/**',
    '.env*',
    '**/*.log',
  ],
  // Include only source files
  include: [
    'app/**/*.{ts,tsx,js,jsx}',
    'lib/**/*.{ts,tsx,js,jsx}',
    'tests/**/*.{ts,tsx,js,jsx}',
    'scripts/**/*.{ts,tsx,js,jsx}',
    'drizzle/**/*.{ts,json,sql}',
    'docs/**/*.md',
    '*.config.{ts,js,cjs,mjs}',
    '*.json',
    '*.md',
  ],
  output: {
    style: 'markdown',
    filePath: 'repomix-output.md',
  },
});
````

## File: tailwind.config.ts
````typescript
import type { Config } from 'tailwindcss';

const config: Config = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: 'hsl(var(--primary))',
        'primary-foreground': 'hsl(var(--primary-foreground))',
        secondary: 'hsl(var(--secondary))',
        'secondary-foreground': 'hsl(var(--secondary-foreground))',
        muted: 'hsl(var(--muted))',
        'muted-foreground': 'hsl(var(--muted-foreground))',
        accent: 'hsl(var(--accent))',
        'accent-foreground': 'hsl(var(--accent-foreground))',
        destructive: 'hsl(var(--destructive))',
        'destructive-foreground': 'hsl(var(--destructive-foreground))',
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
      },
    },
  },
  plugins: [],
};
export default config;
````

## File: tests/api/auth.test.ts
````typescript
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
````

## File: tests/api/users.test.ts
````typescript
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
````

## File: tests/integration/production-paths.test.ts
````typescript
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
````

## File: tests/load/smoke.js
````javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  scenarios: {
    smoke_auth_and_users: {
      executor: 'constant-vus',
      vus: 20,
      duration: '2m',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{endpoint:login}': ['p(95)<250'],
    'http_req_duration{endpoint:users}': ['p(95)<200'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://localhost:3000';

function randomEmail(prefix = 'load') {
  return `${prefix}-${__VU}-${__ITER}@example.com`;
}

export default function smokeScenario() {
  const registerPayload = JSON.stringify({
    email: randomEmail('register'),
    name: 'Load Tester',
    password: 'StrongPassword123!',
  });

  const registerResponse = http.post(`${baseUrl}/api/auth/register`, registerPayload, {
    headers: { 'content-type': 'application/json' },
    tags: { endpoint: 'register' },
  });
  check(registerResponse, { 'register status is 201': (r) => r.status === 201 });

  const loginPayload = JSON.stringify({
    email: randomEmail('login'),
    name: 'Load Login User',
    password: 'StrongPassword123!',
  });

  const preRegister = http.post(`${baseUrl}/api/auth/register`, loginPayload, {
    headers: { 'content-type': 'application/json' },
    tags: { endpoint: 'register' },
  });
  check(preRegister, { 'pre-register status is 201': (r) => r.status === 201 });

  const loginResponse = http.post(
    `${baseUrl}/api/auth/login`,
    JSON.stringify({
      email: JSON.parse(loginPayload).email,
      password: 'StrongPassword123!',
    }),
    {
      headers: { 'content-type': 'application/json' },
      tags: { endpoint: 'login' },
    }
  );

  check(loginResponse, { 'login status is 200': (r) => r.status === 200 });
  const accessToken = loginResponse.json('data.access_token');

  const usersResponse = http.get(`${baseUrl}/api/users?page=1&limit=10`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
    tags: { endpoint: 'users' },
  });

  check(usersResponse, {
    'users request returns expected auth status': (r) => r.status === 200 || r.status === 403,
  });

  sleep(1);
}
````

## File: tests/utils/http-utils.test.ts
````typescript
import { describe, expect, it } from 'vitest';
import { NextRequest } from 'next/server';
import { errorResponse, paginatedResponse, successResponse } from '@/lib/utils/response';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';

describe('Response helpers', () => {
  it('threads explicit requestId through body and header for success responses', async () => {
    const response = successResponse({ ok: true }, 201, 'req-123');
    const payload = await response.json();

    expect(response.status).toBe(201);
    expect(response.headers.get('x-request-id')).toBe('req-123');
    expect(payload.meta.requestId).toBe('req-123');
    expect(payload.success).toBe(true);
  });

  it('generates and mirrors requestId when none is provided', async () => {
    const response = successResponse({ ok: true });
    const payload = await response.json();

    const headerRequestId = response.headers.get('x-request-id');
    expect(headerRequestId).toBeTruthy();
    expect(payload.meta.requestId).toBe(headerRequestId);
  });

  it('includes requestId in error responses', async () => {
    const response = errorResponse('VALIDATION_ERROR', 'Invalid input', 400, { field: 'email' }, 'err-456');
    const payload = await response.json();

    expect(response.status).toBe(400);
    expect(response.headers.get('x-request-id')).toBe('err-456');
    expect(payload.meta.requestId).toBe('err-456');
    expect(payload.error.code).toBe('VALIDATION_ERROR');
  });

  it('returns pagination metadata and requestId in paginated responses', async () => {
    const response = paginatedResponse([{ id: '1' }], 2, 10, 45, 200, 'page-789');
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get('x-request-id')).toBe('page-789');
    expect(payload.meta.pagination.totalPages).toBe(5);
    expect(payload.meta.pagination.page).toBe(2);
  });
});

describe('Request helpers', () => {
  it('returns the first forwarded IP when x-forwarded-for has multiple values', () => {
    const request = new NextRequest('http://localhost/api/demo', {
      headers: { 'x-forwarded-for': '203.0.113.2, 198.51.100.20' },
    });

    expect(getClientIp(request)).toBe('203.0.113.2');
  });

  it('falls back to x-real-ip and then unknown', () => {
    const withRealIp = new NextRequest('http://localhost/api/demo', {
      headers: { 'x-real-ip': '198.51.100.4' },
    });
    const withNoIp = new NextRequest('http://localhost/api/demo');

    expect(getClientIp(withRealIp)).toBe('198.51.100.4');
    expect(getClientIp(withNoIp)).toBe('unknown');
  });

  it('accepts json content-type with charset suffix', () => {
    const request = new NextRequest('http://localhost/api/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json; charset=utf-8' },
      body: JSON.stringify({ hello: 'world' }),
    });

    expect(hasJsonContentType(request)).toBe(true);
  });
});
````

## File: vitest.config.ts
````typescript
import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: {
      NODE_ENV: 'test',
      VERCEL_ENV: 'development',
      JWT_SECRET: '12345678901234567890123456789012',
      JWT_EXPIRY: '15m',
      JWT_REFRESH_EXPIRY: '7d',
      RATE_LIMIT_ENABLED: 'true',
      RATE_LIMIT_WINDOW_MS: '3600000',
      RATE_LIMIT_MAX_REQUESTS: '100',
    },
  },
});
````

## File: docs/API_CONVENTIONS.md
````markdown
# API Conventions

- Keep route files thin: rate-limit + auth + validation + service call + response only.
- Validate all request body/query input with Zod schemas before business logic.
- Return a consistent JSON envelope:
  - Success: `{ success: true, data, meta }`
  - Error: `{ success: false, error, meta }`
- Include request metadata with `timestamp` and `requestId` in responses.
- Include `X-Request-Id` response header on all API responses.
- Enforce role checks in backend middleware and policies, not in frontend pages.
- For auth endpoints, fail closed when rate-limit dependency is unavailable.
- Persist privileged security events to `audit_logs`.
````

## File: docs/ARCHITECTURE.md
````markdown
# Architecture

## Purpose
SwissKnife is a backend-first Next.js App Router starter. It keeps UI minimal and makes API, validation, auth, and middleware the core surface.

## Current layout
- `app/` - route handlers and minimal web entry page.
- `app/api/auth/*` - authentication endpoints.
- `app/api/users/*` - user management endpoints.
- `app/api/health/*` - liveness/readiness probes.
- `lib/auth/*` - token and password helpers.
- `lib/config/*` - environment parsing and runtime flags.
- `lib/db/*` - Drizzle schema, Postgres connection, and repository adapter.
- `lib/middleware/*` - auth and rate-limit guards.
- `lib/platform/*` - external infrastructure adapters (Redis).
- `lib/utils/*` - logging, error normalization, and API responses.
- `lib/validation/*` - Zod request schemas.

## Principles
- Keep route files thin.
- Keep validation explicit at API boundaries.
- Keep auth and authorization in backend code, not UI.
- Keep response envelope consistent across all endpoints.

## Auth Tradeoff
User role and status are embedded in JWTs at issue time.
- Role or status changes do not take effect until the active access token expires.
- Default access token expiry is 15 minutes, so maximum drift is 15 minutes.
- Immediate global revocation requires rotating `JWT_SECRET` and invalidates all active tokens.

This is an intentional tradeoff to avoid a database lookup on every request. If immediate revocation is required, add a token blocklist check in `extractUser`.

## Session Architecture
- Access tokens are short-lived JWTs (`type=access`) and include `sid`.
- Refresh tokens are JWTs (`type=refresh`) with `sid` and `jti`.
- Refresh token hashes are stored server-side (`sha256(token + REFRESH_TOKEN_PEPPER)`).
- Every refresh rotates session state:
  - old session is revoked and linked via `replacedBySessionId`
  - new session row is created with a new `sid` and `jti`
- Reuse detection revokes the entire session family and emits an audit log event.

## Persistence and Rate Limiting
- User/session/audit persistence is in Postgres via Drizzle.
- Rate limiting is distributed via Upstash Redis.
- Auth endpoints fail closed if the rate-limit dependency is unavailable.
````

## File: docs/RUNBOOK.md
````markdown
# Runbook

## Local

1. Copy `.env.example` to `.env.local`.
2. Run `corepack pnpm install`.
3. Run `corepack pnpm db:migrate`.
4. Run `corepack pnpm dev`.
5. Verify routes:
   - `POST /api/auth/register`
   - `POST /api/auth/login`
   - `POST /api/auth/refresh`
   - `POST /api/auth/logout`
   - `GET /api/users`
   - `GET /api/health/live`
   - `GET /api/health/ready`

## Verification

- Run `corepack pnpm verify` before merging changes.
- Run `corepack pnpm test:integration` before releases.
- Run `corepack pnpm db:check` in CI to detect migration/schema drift.
- `verify` may use a temporary in-process `JWT_SECRET` for the build check if none is set in your shell.
- Production and normal runtime still require a real `JWT_SECRET` with at least 32 characters.
- Production also requires `REFRESH_TOKEN_PEPPER`, `DATABASE_URL`, and Upstash Redis credentials.

## Deploy

1. `vercel env add` for required vars.
2. `vercel --prod`.
3. Run smoke check against production URL:
   - `GET /api/health/live` returns 200.
   - `GET /api/health/ready` returns 200.
   - Register/login/refresh/logout flow succeeds.

## Proxy and Rate Limit Safety
- `TRUST_PROXY` must match your deployment model.
- If running behind a load balancer or reverse proxy, ensure it sets `x-forwarded-for`.
- If running directly on the internet without trusted proxy headers, IP-based rate limiting is not reliable.

## Secret Rotation
- Rotate `JWT_SECRET` for global token invalidation events.
- Rotate `REFRESH_TOKEN_PEPPER` to invalidate stored refresh token hashes.
- Rotation checklist:
  1. Add new secret in platform env.
  2. Deploy.
  3. Revoke active sessions if incident-driven.
  4. Monitor auth error rates for 30 minutes.

## Incident Playbooks
- Database outage:
  1. Confirm `/api/health/ready` dependency detail.
  2. Fail traffic over/restore Neon connectivity.
  3. Re-run smoke auth flow.
- Redis outage:
  1. Auth endpoints fail closed by design.
  2. Restore Upstash connectivity.
  3. Confirm login/register/refresh return 2xx/4xx again.
- Refresh token reuse spike:
  1. Query `audit_logs` for `auth.refresh_reuse_detected`.
  2. Revoke suspicious session families.
  3. Rotate `JWT_SECRET` if compromise suspected.
````

## File: package.json
````json
{
  "name": "swissknife",
  "version": "2.0.0",
  "description": "Backend-first Next.js template for authentication and user management foundations.",
  "private": true,
  "license": "MIT",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "build:verify": "node scripts/build-verify.mjs",
    "start": "next start",
    "lint": "eslint .",
    "test": "vitest run",
    "test:unit": "vitest run tests/api tests/utils",
    "test:integration": "vitest run tests/integration",
    "type-check": "next typegen && tsc --noEmit",
    "verify": "npm run type-check && npm run lint && npm run test:unit && npm run build:verify",
    "db:generate": "drizzle-kit generate",
    "db:migrate": "drizzle-kit migrate",
    "db:check": "drizzle-kit check",
    "format": "prettier --write ."
  },
  "engines": {
    "node": ">=20"
  },
  "dependencies": {
    "@opentelemetry/api": "^1.9.0",
    "@sentry/node": "^10.22.0",
    "@upstash/ratelimit": "^2.0.7",
    "@upstash/redis": "^1.35.6",
    "bcryptjs": "^2.4.3",
    "drizzle-orm": "^0.44.6",
    "jose": "^5.1.3",
    "next": "^15.0.0",
    "postgres": "^3.4.7",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "zod": "^3.22.4"
  },
  "devDependencies": {
    "@types/bcryptjs": "^2.4.2",
    "@types/node": "^20",
    "@types/react": "^18",
    "@types/react-dom": "^18",
    "autoprefixer": "^10",
    "drizzle-kit": "^0.31.6",
    "eslint": "^8",
    "eslint-config-next": "^15",
    "postcss": "^8",
    "prettier": "^3.2.5",
    "repomix": "^1.12.0",
    "tailwindcss": "^3",
    "typescript": "^5",
    "vite-tsconfig-paths": "^6.1.1",
    "vitest": "^4.0.18"
  }
}
````

## File: README.md
````markdown
# SwissKnife

Production-grade backend-first Next.js App Router starter for auth and user management foundations.

## Highlights
- Secure-by-default auth flow (`register`, `login`, `refresh`, `logout`, protected routes).
- Postgres persistence via Drizzle (`users`, `sessions`, `audit_logs`).
- Refresh token rotation with reuse detection and session revocation.
- Distributed rate limiting via Upstash Redis with fail-open/fail-closed policies.
- Health probes (`/api/health/live`, `/api/health/ready`) for deployment readiness checks.
- Consistent API envelope with `meta.requestId` and `X-Request-Id`.
- Input validation with Zod at route boundaries.
- Structured JSON logging with sensitive-field redaction.

## Security Defaults
- Public registration cannot escalate role (`role` is forced to `user`).
- Login path includes timing-attack mitigation for unknown emails.
- Access and refresh tokens are type-scoped (`type: access | refresh`) and session-bound (`sid`).
- Refresh tokens are hashed at rest (`sha256(token + REFRESH_TOKEN_PEPPER)`).
- Refresh token reuse revokes the full session family.
- API and app responses include baseline security headers.
- Environment variables are validated on startup, including strict production guards.

## Requirements
- Node.js `>=20`
- npm (or pnpm via Corepack)

## Quick Start
```bash
npm install
cp .env.example .env.local
npm run db:migrate
npm run dev
```

Open `http://localhost:3000`.

## Verification and Testing
```bash
npm run type-check
npm run lint
npm run test
npm run verify
```

`npm run verify` runs a production build check. If `JWT_SECRET` is not set in your shell, the verify build uses a temporary in-process value only for that verification command. Runtime security is unchanged: normal app startup still enforces `JWT_SECRET` validation.

## Environment Variables
See `.env.example`.

Required for production runtime:
- `JWT_SECRET` (minimum 32 chars)
- `REFRESH_TOKEN_PEPPER` (minimum 16 chars)
- `DATABASE_URL`
- `UPSTASH_REDIS_REST_URL`
- `UPSTASH_REDIS_REST_TOKEN`

Development/test overrides:
- `ALLOW_IN_MEMORY_DB` (default `false`)
- `ALLOW_IN_MEMORY_RATE_LIMIT` (default `false`)

Optional:
- `JWT_EXPIRY` (default `15m`)
- `JWT_REFRESH_EXPIRY` (default `7d`)
- `SENTRY_DSN`
- `OTEL_EXPORTER_OTLP_ENDPOINT`

## API Endpoints
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout`
- `GET /api/health/live`
- `GET /api/health/ready`
- `GET /api/users` (admin/superadmin)
- `GET /api/users/:id` (self or admin/superadmin)
- `PATCH /api/users/:id` (self; role edits require admin/superadmin)
- `DELETE /api/users/:id` (admin/superadmin)

## Project Structure
- `app/api/*` - route handlers
- `lib/auth/*` - JWT/password helpers
- `lib/config/*` - env parsing and runtime guards
- `lib/db/*` - Drizzle schema, connection, and repository adapter
- `lib/middleware/*` - auth and rate limiting
- `lib/platform/*` - infrastructure adapters (Redis)
- `lib/utils/*` - responses, request helpers, logger, errors
- `lib/validation/*` - Zod schemas
- `tests/*` - API and utility tests

## Additional Docs
- [Quick Start](./QUICK_START.md)
- [Architecture](./docs/ARCHITECTURE.md)
- [Runbook](./docs/RUNBOOK.md)
- [Testing](./docs/TESTING.md)
````

## File: tsconfig.json
````json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": [
      "ES2020",
      "DOM",
      "DOM.Iterable"
    ],
    "module": "ESNext",
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "noEmit": true,
    "resolveJsonModule": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "isolatedModules": true,
    "jsx": "preserve",
    "incremental": true,
    "plugins": [
      {
        "name": "next"
      }
    ],
    "paths": {
      "@/*": [
        "./*"
      ]
    },
    "allowJs": true
  },
  "include": [
    "**/*.ts",
    "**/*.tsx",
    "next-env.d.ts",
    ".next/types/**/*.ts"
  ],
  "exclude": [
    "node_modules"
  ]
}
````

## File: vercel.json
````json
{
  "buildCommand": "next build",
  "outputDirectory": ".next",
  "framework": "nextjs",
  "regions": ["iad1"],
  "functions": {
    "app/api/**": {
      "maxDuration": 30,
      "memory": 1024
    }
  },
  "env": [
    "NODE_ENV",
    "JWT_SECRET",
    "REFRESH_TOKEN_PEPPER",
    "JWT_EXPIRY",
    "JWT_REFRESH_EXPIRY",
    "DATABASE_URL",
    "UPSTASH_REDIS_REST_URL",
    "UPSTASH_REDIS_REST_TOKEN",
    "RATE_LIMIT_ENABLED",
    "RATE_LIMIT_WINDOW_MS",
    "RATE_LIMIT_MAX_REQUESTS",
    "SENTRY_DSN",
    "OTEL_EXPORTER_OTLP_ENDPOINT"
  ]
}
````
