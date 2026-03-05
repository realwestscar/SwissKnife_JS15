This file is a merged representation of a subset of the codebase, containing specifically included files and files not matching ignore patterns, combined into a single document by Repomix.

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
- Only files matching these patterns are included: app/**/*.{ts,tsx,js,jsx,css}, lib/**/*.{ts,tsx,js,jsx}, tests/**/*.{ts,tsx,js,jsx}, scripts/**/*.{ts,tsx,js,jsx,mjs}, drizzle/**/*.{ts,json,sql}, decisions/**/*.md, docs/**/*.md, *.config.{ts,js,cjs,mjs}, *.json, *.md, .env.example, docker-compose.yml
- Files matching these patterns are excluded: **/node_modules/**, **/.next/**, **/dist/**, **/build/**, tsconfig.tsbuildinfo, *.lock, pnpm-lock.yaml, package-lock.json, .git/**, .env.local, .env.production, **/*.log
- Files matching patterns in .gitignore are excluded
- Files matching default ignore patterns are excluded
- Files are sorted by Git change count (files with more changes are at the bottom)

# Directory Structure
```
.env.example
app/api/auth/forgot-password/route.ts
app/api/auth/login/route.ts
app/api/auth/logout/route.ts
app/api/auth/refresh/route.ts
app/api/auth/register/route.ts
app/api/auth/reset-password/route.ts
app/api/auth/verify-email/route.ts
app/api/health/live/route.ts
app/api/health/ready/route.ts
app/api/users/[id]/route.ts
app/api/users/route.ts
app/globals.css
app/layout.tsx
app/page.tsx
CLAUDE.md
CONTRIBUTING.md
decisions/001-drizzle-over-prisma.md
decisions/002-jose-for-jwt.md
decisions/003-upstash-for-rate-limiting.md
decisions/004-bcryptjs-for-passwords.md
decisions/005-zod-for-validation.md
docker-compose.yml
docs/API_CONVENTIONS.md
docs/ARCHITECTURE.md
docs/internal/NEXT16_WORLD_CLASS_BASELINE_SCOPE.md
docs/RUNBOOK.md
docs/TESTING.md
drizzle.config.ts
drizzle/0000_lush_prima.sql
drizzle/0001_auth_tokens_and_email_verification.sql
drizzle/meta/_journal.json
drizzle/meta/0000_snapshot.json
lib/auth/jwt.ts
lib/auth/password.ts
lib/auth/session-security.ts
lib/auth/session-service.ts
lib/auth/token-hash.ts
lib/config/env.ts
lib/db/client.ts
lib/db/connection.ts
lib/db/schema.ts
lib/middleware/auth.ts
lib/middleware/rate-limit.ts
lib/observability/monitoring.ts
lib/platform/redis.ts
lib/types/db.ts
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
scripts/build-verify.mjs
scripts/db-reset.mjs
scripts/seed.mjs
SECURITY.md
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

## File: app/api/auth/forgot-password/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db/client';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';
import { errorResponse, successResponse } from '@/lib/utils/response';
import { ValidationError, getErrorDetails } from '@/lib/utils/errors';
import { generateOpaqueToken, hashOpaqueToken } from '@/lib/auth/token-hash';
import { logger } from '@/lib/utils/logger';
import { captureException } from '@/lib/observability/monitoring';
import { env } from '@/lib/config/env';

const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
});

const FORGOT_PASSWORD_IP_POLICY = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  failOpen: false,
} as const;

const FORGOT_PASSWORD_EMAIL_POLICY = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 5,
  failOpen: false,
} as const;

const GENERIC_RESPONSE = { message: 'If the account exists, a password reset email has been sent.' };

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    await checkRateLimit(`forgot-password:ip:${ip}`, FORGOT_PASSWORD_IP_POLICY);

    if (!hasJsonContentType(request)) {
      throw new ValidationError('Content-Type must be application/json');
    }

    const body = await request.json();
    const parsed = forgotPasswordSchema.safeParse(body);
    if (!parsed.success) {
      throw new ValidationError('Invalid input', { errors: parsed.error.flatten() });
    }

    const email = parsed.data.email.toLowerCase();
    await checkRateLimit(`forgot-password:email:${email}`, FORGOT_PASSWORD_EMAIL_POLICY);

    const user = await db.findUserByEmail(email);
    if (!user) {
      return successResponse(GENERIC_RESPONSE, 200, requestId);
    }

    const token = generateOpaqueToken();
    const tokenHash = hashOpaqueToken(token);
    await db.createPasswordResetToken(user.id, tokenHash, new Date(Date.now() + 60 * 60 * 1000));

    await db.createAuditLog({
      userId: user.id,
      actorUserId: user.id,
      eventType: 'auth.password_reset_requested',
      requestId,
      ipAddress: ip,
      userAgent,
    });

    const data =
      env.NODE_ENV === 'test' ? { ...GENERIC_RESPONSE, reset_token: token } : GENERIC_RESPONSE;

    return successResponse(data, 200, requestId);
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/forgot-password' });
    logger.error('Forgot password failed', details, requestId, {
      endpoint: '/api/auth/forgot-password',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

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

## File: app/api/auth/reset-password/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { z } from 'zod';
import { db } from '@/lib/db/client';
import { hashPassword } from '@/lib/auth/password';
import { hashOpaqueToken } from '@/lib/auth/token-hash';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { getClientIp, hasJsonContentType } from '@/lib/utils/request';
import { errorResponse, successResponse } from '@/lib/utils/response';
import { AuthenticationError, ValidationError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { captureException } from '@/lib/observability/monitoring';

const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Token is required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
});

const RESET_PASSWORD_POLICY = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 10,
  failOpen: false,
} as const;

export async function POST(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    await checkRateLimit(`reset-password:ip:${ip}`, RESET_PASSWORD_POLICY);

    if (!hasJsonContentType(request)) {
      throw new ValidationError('Content-Type must be application/json');
    }

    const body = await request.json();
    const parsed = resetPasswordSchema.safeParse(body);
    if (!parsed.success) {
      throw new ValidationError('Invalid input', { errors: parsed.error.flatten() });
    }

    const tokenHash = hashOpaqueToken(parsed.data.token);
    const record = await db.findPasswordResetToken(tokenHash);
    if (!record || record.usedAt || record.expiresAt.getTime() <= Date.now()) {
      throw new AuthenticationError('Invalid or expired password reset token');
    }

    const user = await db.findUserById(record.userId);
    if (!user) {
      throw new AuthenticationError('Invalid or expired password reset token');
    }

    await db.updateUser(user.id, { passwordHash: await hashPassword(parsed.data.password) });
    await db.markPasswordResetTokenUsed(tokenHash);
    await db.revokeAllSessionsForUser(user.id);

    await db.createAuditLog({
      userId: user.id,
      actorUserId: user.id,
      eventType: 'auth.password_reset_completed',
      requestId,
      ipAddress: ip,
      userAgent,
    });

    return successResponse({ message: 'Password has been reset' }, 200, requestId);
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/reset-password' });
    logger.error('Reset password failed', details, requestId, {
      endpoint: '/api/auth/reset-password',
      status: details.status,
      latencyMs: Date.now() - startTime,
    });

    return errorResponse(details.code, details.message, details.status, details.details, requestId);
  }
}
````

## File: app/api/auth/verify-email/route.ts
````typescript
import { type NextRequest } from 'next/server';
import { db } from '@/lib/db/client';
import { hashOpaqueToken } from '@/lib/auth/token-hash';
import { checkRateLimit } from '@/lib/middleware/rate-limit';
import { getClientIp } from '@/lib/utils/request';
import { errorResponse, successResponse } from '@/lib/utils/response';
import { AuthenticationError, ValidationError, getErrorDetails } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';
import { captureException } from '@/lib/observability/monitoring';

const VERIFY_EMAIL_POLICY = {
  windowMs: 15 * 60 * 1000,
  maxRequests: 20,
  failOpen: false,
} as const;

export async function GET(request: NextRequest) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const ip = getClientIp(request);
  const userAgent = request.headers.get('user-agent') || 'unknown';

  try {
    await checkRateLimit(`verify-email:ip:${ip}`, VERIFY_EMAIL_POLICY);

    const token = new URL(request.url).searchParams.get('token');
    if (!token) {
      throw new ValidationError('Verification token is required');
    }

    const tokenHash = hashOpaqueToken(token);
    const record = await db.findEmailVerificationToken(tokenHash);
    if (!record || record.usedAt || record.expiresAt.getTime() <= Date.now()) {
      throw new AuthenticationError('Invalid or expired verification token');
    }

    await db.markEmailVerified(record.userId);
    await db.markEmailVerificationTokenUsed(tokenHash);

    await db.createAuditLog({
      userId: record.userId,
      actorUserId: record.userId,
      eventType: 'auth.email_verified',
      requestId,
      ipAddress: ip,
      userAgent,
    });

    return successResponse({ message: 'Email verified successfully' }, 200, requestId);
  } catch (error) {
    const details = getErrorDetails(error);
    captureException(error, { requestId, endpoint: '/api/auth/verify-email' });
    logger.error('Email verification failed', details, requestId, {
      endpoint: '/api/auth/verify-email',
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

## File: app/globals.css
````css
@tailwind base;
@tailwind components;
@tailwind utilities;

@layer base {
  :root {
    color-scheme: dark;
    --background: 0 0% 5.9%;
    --foreground: 0 0% 98%;
    --primary: 0 0% 100%;
    --primary-foreground: 0 0% 0%;
    --secondary: 220 13% 20%;
    --secondary-foreground: 0 0% 98%;
    --muted: 220 13% 20%;
    --muted-foreground: 0 0% 62%;
    --accent: 0 0% 100%;
    --accent-foreground: 0 0% 0%;
    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 0 0% 98%;
    --border: 220 13% 18%;
    --input: 220 13% 12%;
    --ring: 0 0% 100%;
    --radius: 0.375rem;
  }
}

@layer base {
  * {
    @apply border-border;
  }
  body {
    @apply bg-background text-foreground;
    font-feature-settings: 'rlig' 1, 'calt' 1;
  }
  h1, h2, h3, h4, h5, h6 {
    @apply font-semibold;
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
            <li><code>POST /api/auth/forgot-password</code></li>
            <li><code>POST /api/auth/reset-password</code></li>
            <li><code>GET /api/auth/verify-email</code></li>
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

## File: CONTRIBUTING.md
````markdown
# Contributing

## Setup

1. `corepack pnpm install`
2. `cp .env.example .env.local`
3. `corepack pnpm db:migrate`
4. `corepack pnpm dev`

## Conventions

- Keep route handlers thin: middleware -> validation -> module/service -> response helper.
- Use canonical API envelopes for success/error responses.
- Add or update tests for behavior changes (`test:unit`, and `test:integration` when infra behavior changes).
- Prefer adapter-based implementations over direct infra calls inside route files.

## PR process

1. Branch from `main`.
2. Run:
   - `corepack pnpm test:unit`
   - `corepack pnpm db:migrate`
   - `corepack pnpm test:integration`
3. Open a PR with a concise summary, validation steps, and any migration/env impact.
````

## File: decisions/001-drizzle-over-prisma.md
````markdown
# 001: Use Drizzle Over Prisma

## Status
Accepted

## Decision
Use Drizzle ORM as the default database access layer.

## Why
- SQL-first migrations are easy to inspect in code review.
- Tight TypeScript inference without generated runtime clients.
- Works cleanly with adapter-based architecture.

## Consequences
- Team writes more explicit SQL-aware schema/migration code.
- Migration discipline stays in-repo via `drizzle/*.sql`.
````

## File: decisions/002-jose-for-jwt.md
````markdown
# 002: Use jose For JWT

## Status
Accepted

## Decision
Use `jose` for JWT signing and verification.

## Why
- Standards-compliant and security-focused implementation.
- Clear APIs for signing, verification, and claim handling.
- Better long-term maintenance than ad hoc token utilities.

## Consequences
- Token claim contracts must stay explicit and tested.
- Auth middleware must enforce token type and required claims.
````

## File: decisions/003-upstash-for-rate-limiting.md
````markdown
# 003: Use Upstash For Rate Limiting

## Status
Accepted

## Decision
Use Upstash Redis as the default rate-limit backend.

## Why
- Serverless-friendly and operationally simple.
- Works with global deployments where in-memory counters fail.
- Integrates directly with `@upstash/ratelimit`.

## Consequences
- Redis dependency availability affects auth endpoints.
- `failOpen` policy must be chosen per endpoint risk.
````

## File: decisions/004-bcryptjs-for-passwords.md
````markdown
# 004: Use bcryptjs For Passwords

## Status
Accepted

## Decision
Use `bcryptjs` for password hashing and verification.

## Why
- Proven adaptive hashing algorithm for password storage.
- Works in Node runtimes without external native setup.
- Existing code and tests already depend on bcrypt semantics.

## Consequences
- Cost factor tuning is required as hardware changes.
- Hash/compare calls must remain on trusted server paths only.
````

## File: decisions/005-zod-for-validation.md
````markdown
# 005: Use zod For Validation

## Status
Accepted

## Decision
Use `zod` for request boundary validation.

## Why
- Type-safe runtime validation from a single schema source.
- Clear error flattening for consistent API error payloads.
- Lightweight and already adopted across routes.

## Consequences
- All endpoints should validate input before authorization logic that depends on parsed data.
- Validation schemas are part of API contract and must be versioned with care.
````

## File: docker-compose.yml
````yaml
version: '3.9'
services:
  postgres:
    image: postgres:16
    container_name: swissknife-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: swissknife
    ports:
      - '5432:5432'
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ['CMD-SHELL', 'pg_isready -U postgres -d swissknife']
      interval: 5s
      timeout: 5s
      retries: 10

  redis:
    image: redis:7
    container_name: swissknife-redis
    restart: unless-stopped
    ports:
      - '6379:6379'
    volumes:
      - redis_data:/data
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 5s
      timeout: 5s
      retries: 10

volumes:
  postgres_data:
  redis_data:
````

## File: docs/API_CONVENTIONS.md
````markdown
# API Conventions

## Route shape

Keep route handlers thin and consistent:
1. Parse request metadata.
2. Apply rate-limit/auth middleware.
3. Validate input with Zod schemas.
4. Call module/service logic.
5. Return canonical response envelope.

## Response formats

- Success: `{ success: true, data, meta }`
- Error: `{ success: false, error, meta }`

`meta` includes `requestId` and timestamp, and responses include `X-Request-Id`.

## Error handling

- Validate at boundaries before business logic.
- Normalize known errors to stable error codes.
- Enforce role checks server-side only.
````

## File: docs/ARCHITECTURE.md
````markdown
# Architecture

SwissKnife follows a thin-route, module-first architecture:

```text
Request
  -> Middleware (rate-limit, auth)
  -> Route handler (App Router)
  -> Module/service logic
  -> Adapter
  -> Infrastructure (Postgres, Redis, optional S3/Inngest/Resend)
```

## What is true now

- Route handlers are in `app/api/**` and should stay thin.
- Environment and adapter guardrails are centralized in `lib/config/env.ts`.
- Auth/session behavior lives in `lib/auth/*` with rotation + reuse detection.
- Persistence is implemented with Drizzle/Postgres in `lib/db/*`.
- Rate limiting is implemented through Redis adapter paths in `lib/platform/*` and middleware.
- Response and error envelopes are standardized via utility helpers.
````

## File: docs/internal/NEXT16_WORLD_CLASS_BASELINE_SCOPE.md
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

## File: docs/RUNBOOK.md
````markdown
# Runbook

## Local startup

1. `corepack pnpm install`
2. `cp .env.example .env.local`
3. `corepack pnpm db:migrate`
4. `corepack pnpm dev`

## Pre-merge checks

1. `corepack pnpm test:unit`
2. `corepack pnpm db:migrate`
3. `corepack pnpm test:integration`

## Production readiness

- Configure required envs: `JWT_SECRET`, `REFRESH_TOKEN_PEPPER`, `DATABASE_URL`.
- Configure Redis credentials unless intentionally using in-memory mode outside production.
- Verify health endpoints:
  - `/api/health/live`
  - `/api/health/ready`

## Incident notes

- DB outage: restore database connectivity first, then re-run readiness checks.
- Redis outage: restore Redis/upstream availability, then re-check auth-related paths.
- Suspected token compromise: rotate secrets and revoke sessions.
````

## File: docs/TESTING.md
````markdown
# Testing

## Commands

```bash
corepack pnpm test:unit
corepack pnpm db:migrate
corepack pnpm test:integration
```

## Current test intent

- Unit/API tests verify auth, users, validation, response envelope, and helper behavior.
- Integration tests verify production-style adapter paths and readiness behavior.

## Test authoring rules

- Place tests in `tests/**/*.test.ts`.
- Prefer route-level behavior tests for API contracts.
- Assert status code and canonical response shape.
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

## File: drizzle/0001_auth_tokens_and_email_verification.sql
````sql
ALTER TABLE "users" ADD COLUMN "email_verified_at" timestamp with time zone;
--> statement-breakpoint
CREATE TABLE "password_reset_tokens" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "email_verification_tokens" (
	"token_hash" text PRIMARY KEY NOT NULL,
	"user_id" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "password_reset_tokens" ADD CONSTRAINT "password_reset_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "email_verification_tokens" ADD CONSTRAINT "email_verification_tokens_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX "password_reset_tokens_user_idx" ON "password_reset_tokens" USING btree ("user_id");
--> statement-breakpoint
CREATE INDEX "password_reset_tokens_expires_at_idx" ON "password_reset_tokens" USING btree ("expires_at");
--> statement-breakpoint
CREATE INDEX "email_verification_tokens_user_idx" ON "email_verification_tokens" USING btree ("user_id");
--> statement-breakpoint
CREATE INDEX "email_verification_tokens_expires_at_idx" ON "email_verification_tokens" USING btree ("expires_at");
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

## File: lib/auth/token-hash.ts
````typescript
import crypto from 'crypto';
import { env } from '@/lib/config/env';

export function generateOpaqueToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashOpaqueToken(token: string): string {
  return crypto.createHash('sha256').update(`${token}:${env.REFRESH_TOKEN_PEPPER}`).digest('hex');
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

## File: lib/types/db.ts
````typescript
import { type User } from '@/lib/types';

export interface DatabaseUser extends User {
  emailVerifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
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

export interface PasswordResetTokenRecord {
  tokenHash: string;
  userId: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
}

export interface EmailVerificationTokenRecord {
  tokenHash: string;
  userId: string;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
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

export interface DatabaseClient {
  initialize(): Promise<void>;
  healthCheck(): Promise<boolean>;
  findUserByEmail(email: string): Promise<DatabaseUser | null>;
  findUserById(id: string): Promise<DatabaseUser | null>;
  createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt' | 'emailVerifiedAt'>): Promise<DatabaseUser>;
  updateUser(id: string, updates: Partial<Omit<DatabaseUser, 'id' | 'createdAt'>>): Promise<DatabaseUser | null>;
  deleteUser(id: string): Promise<boolean>;
  getAllUsers(page?: number, limit?: number): Promise<UserListResult>;
  searchUsers(query: string, page?: number, limit?: number): Promise<UserListResult>;
  createSession(session: CreateSessionInput): Promise<SessionRecord>;
  findSessionById(sessionId: string): Promise<SessionRecord | null>;
  rotateSession(input: RotateSessionInput): Promise<SessionRecord>;
  revokeSession(sessionId: string): Promise<boolean>;
  revokeSessionFamily(familyId: string): Promise<number>;
  revokeAllSessionsForUser(userId: string): Promise<number>;
  markSessionReuseDetected(sessionId: string): Promise<void>;
  createPasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  findPasswordResetToken(tokenHash: string): Promise<PasswordResetTokenRecord | null>;
  markPasswordResetTokenUsed(tokenHash: string): Promise<void>;
  createEmailVerificationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void>;
  findEmailVerificationToken(tokenHash: string): Promise<EmailVerificationTokenRecord | null>;
  markEmailVerificationTokenUsed(tokenHash: string): Promise<void>;
  markEmailVerified(userId: string): Promise<void>;
  createAuditLog(log: AuditLogInput): Promise<void>;
  reset(): Promise<void>;
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

## File: scripts/build-verify.mjs
````javascript
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const nextBin = require.resolve('next/dist/bin/next');

const env = { ...process.env };

if (!env.JWT_SECRET) {
  env.JWT_SECRET = 'verify-build-secret-123456789012345';
  console.warn('[verify] JWT_SECRET is not set; using a temporary value for local build verification only.');
}

if (!env.REFRESH_TOKEN_PEPPER) {
  env.REFRESH_TOKEN_PEPPER = 'verify-refresh-token-pepper-12345';
  console.warn('[verify] REFRESH_TOKEN_PEPPER is not set; using a temporary value for local build verification only.');
}

if (!env.ALLOW_IN_MEMORY_DB) {
  env.ALLOW_IN_MEMORY_DB = 'true';
}

if (!env.ALLOW_IN_MEMORY_RATE_LIMIT) {
  env.ALLOW_IN_MEMORY_RATE_LIMIT = 'true';
}

env.BUILD_VERIFY = 'true';

const result = spawnSync(process.execPath, [nextBin, 'build'], {
  stdio: 'inherit',
  env,
});

if (result.error) {
  console.error('[verify] Failed to run Next.js build:', result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
````

## File: scripts/db-reset.mjs
````javascript
import { execSync } from 'node:child_process';
import postgres from 'postgres';

const nodeEnv = process.env.NODE_ENV ?? 'development';
if (nodeEnv === 'production') {
  throw new Error('Refusing to reset database in production');
}

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}

const sql = postgres(process.env.DATABASE_URL, { prepare: false });

try {
  await sql`drop schema public cascade`;
  await sql`create schema public`;
  await sql`grant all on schema public to postgres`;
  await sql`grant all on schema public to public`;
} finally {
  await sql.end({ timeout: 5 });
}

execSync('npm.cmd run db:migrate', { stdio: 'inherit' });
execSync('node scripts/seed.mjs', { stdio: 'inherit' });

console.log('Database reset completed');
````

## File: scripts/seed.mjs
````javascript
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

const nodeEnv = process.env.NODE_ENV ?? 'development';
if (nodeEnv === 'production') {
  throw new Error('Refusing to run seed in production');
}

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is required');
}

const sql = postgres(process.env.DATABASE_URL, { prepare: false });

async function upsertUser(email, name, role) {
  const passwordHash = await bcrypt.hash('ChangeMe123!', 10);
  const now = new Date();
  await sql`
    insert into users (id, email, name, password_hash, role, status, created_at, updated_at, email_verified_at)
    values (${crypto.randomUUID()}, ${email}, ${name}, ${passwordHash}, ${role}, 'active', ${now}, ${now}, ${now})
    on conflict (email) do update
    set
      name = excluded.name,
      role = excluded.role,
      status = excluded.status,
      password_hash = excluded.password_hash,
      email_verified_at = excluded.email_verified_at,
      updated_at = excluded.updated_at
  `;
}

try {
  await upsertUser('superadmin@swissknife.dev', 'Super Admin', 'superadmin');
  await upsertUser('admin@swissknife.dev', 'Admin User', 'admin');
  await upsertUser('user1@swissknife.dev', 'User One', 'user');
  await upsertUser('user2@swissknife.dev', 'User Two', 'user');
  await upsertUser('user3@swissknife.dev', 'User Three', 'user');
  await upsertUser('user4@swissknife.dev', 'User Four', 'user');
  await upsertUser('user5@swissknife.dev', 'User Five', 'user');
  console.log('Seed completed');
} finally {
  await sql.end({ timeout: 5 });
}
````

## File: SECURITY.md
````markdown
# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via your internal security/contact channel rather than opening a public issue.

Include:
- Affected area and impact
- Reproduction steps or proof of concept
- Suggested mitigation (if available)

## Security baseline

- JWT and refresh-token secrets are required in production.
- Refresh tokens are rotated and reuse is detected/revoked.
- Environment variables are validated at startup.
- Auth-related routes are rate limited.

## Operational response

- Rotate `JWT_SECRET` for global token invalidation events.
- Rotate `REFRESH_TOKEN_PEPPER` for refresh-token hash invalidation.
- Revoke active sessions when compromise is suspected.
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

    // Delete user
    const deleted = await db.deleteUser(id);
    if (!deleted) {
      throw new NotFoundError('User not found');
    }

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

## File: CLAUDE.md
````markdown
# CLAUDE.md

SwissKnife is a backend-first Next.js App Router template focused on secure auth and maintainable API foundations.

## Where Things Live

- Auth logic: `lib/auth/*` and auth routes under `app/api/auth/*`
- Domain modules: route handlers in `app/api/**` and services/repositories in `lib/**`
- Validation: `lib/validation/schemas.ts`

## Key Conventions

- Error format: `{ success: false, error, meta }`
- Response format: `{ success: true, data, meta }`
- Pipeline order: request -> rate limit/auth middleware -> validation -> service -> response helper
- Update rule: update `CLAUDE.md` in the same commit as any convention change

## Worked Example: Add A Protected Endpoint

1. Add `app/api/projects/route.ts`.
2. In handler order:
   - `await checkRateLimit(...)`
   - `const user = await extractUser(request); requireAuth(user); requireRole(user, 'admin', 'superadmin')`
   - Validate body/query with zod schema
   - Call DB/service logic
   - Return `successResponse(...)`
3. Add tests under `tests/api/projects.test.ts` for:
   - missing token -> `401`
   - non-admin -> `403`
   - valid admin path -> `200`

## Worked Example: Add A Drizzle Migration

1. Update table model in `lib/db/schema.ts`.
2. Generate migration:
   - `corepack pnpm db:generate`
3. Verify SQL in `drizzle/*.sql`.
4. Apply locally:
   - `corepack pnpm db:migrate`
5. Add/adjust tests that cover the new DB behavior.

## Worked Example: Add A New Error Class

1. Add class in `lib/utils/errors.ts` extending `AppError`.
2. Set stable code/status pair (example: `new AppError('PAYMENT_REQUIRED', 402, ...)`).
3. Throw only at domain boundary, not deep utility layers unless required.
4. Add a test to confirm route returns expected `error.code` and HTTP status.

## Never Do This

- Do not bypass zod validation for request input.
- Do not return raw thrown errors directly to clients.
- Do not hardcode fallback identities (example: `name: 'User'`) in auth middleware.
- Do not use `ALLOW_IN_MEMORY_*` flags in production.
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
    },
    {
      "idx": 1,
      "version": "7",
      "when": 1772677200000,
      "tag": "0001_auth_tokens_and_email_verification",
      "breakpoints": true
    }
  ]
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
    name: user.name,
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

## File: lib/db/client.ts
````typescript
import crypto from 'crypto';
import { and, count, desc, eq, ilike, isNull, or } from 'drizzle-orm';
import { env } from '@/lib/config/env';
import { checkDatabaseHealth, getDrizzleClient } from '@/lib/db/connection';
import {
  auditLogs,
  emailVerificationTokens,
  passwordResetTokens,
  sessions,
  users,
  type AuditLogRow,
  type EmailVerificationTokenRow,
  type PasswordResetTokenRow,
  type SessionRow,
  type UserRow,
} from '@/lib/db/schema';
import {
  type AuditLogInput,
  type CreateSessionInput,
  type DatabaseClient,
  type DatabaseUser,
  type EmailVerificationTokenRecord,
  type PasswordResetTokenRecord,
  type RotateSessionInput,
  type SessionRecord,
} from '@/lib/types/db';
import { logger } from '@/lib/utils/logger';

export type {
  AuditLogInput,
  CreateSessionInput,
  DatabaseClient,
  DatabaseUser,
  EmailVerificationTokenRecord,
  PasswordResetTokenRecord,
  RotateSessionInput,
  SessionRecord,
} from '@/lib/types/db';

interface UserListResult {
  users: DatabaseUser[];
  total: number;
}

function mapUserRow(row: UserRow): DatabaseUser {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    passwordHash: row.passwordHash,
    role: row.role,
    status: row.status,
    emailVerifiedAt: row.emailVerifiedAt,
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

function mapPasswordResetTokenRow(row: PasswordResetTokenRow): PasswordResetTokenRecord {
  return {
    tokenHash: row.tokenHash,
    userId: row.userId,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
  };
}

function mapEmailVerificationTokenRow(row: EmailVerificationTokenRow): EmailVerificationTokenRecord {
  return {
    tokenHash: row.tokenHash,
    userId: row.userId,
    expiresAt: row.expiresAt,
    usedAt: row.usedAt,
    createdAt: row.createdAt,
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

  async createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt' | 'emailVerifiedAt'>): Promise<DatabaseUser> {
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

  async revokeAllSessionsForUser(userId: string): Promise<number> {
    const drizzle = getDrizzleClient();
    const revoked = await drizzle
      .update(sessions)
      .set({ revokedAt: new Date(), updatedAt: new Date() })
      .where(and(eq(sessions.userId, userId), isNull(sessions.revokedAt)))
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

  async createPasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle.insert(passwordResetTokens).values({
      tokenHash,
      userId,
      expiresAt,
      createdAt: new Date(),
      usedAt: null,
    });
  }

  async findPasswordResetToken(tokenHash: string): Promise<PasswordResetTokenRecord | null> {
    const drizzle = getDrizzleClient();
    const [token] = await drizzle.select().from(passwordResetTokens).where(eq(passwordResetTokens.tokenHash, tokenHash)).limit(1);
    return token ? mapPasswordResetTokenRow(token) : null;
  }

  async markPasswordResetTokenUsed(tokenHash: string): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle
      .update(passwordResetTokens)
      .set({ usedAt: new Date() })
      .where(eq(passwordResetTokens.tokenHash, tokenHash));
  }

  async createEmailVerificationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle.insert(emailVerificationTokens).values({
      tokenHash,
      userId,
      expiresAt,
      createdAt: new Date(),
      usedAt: null,
    });
  }

  async findEmailVerificationToken(tokenHash: string): Promise<EmailVerificationTokenRecord | null> {
    const drizzle = getDrizzleClient();
    const [token] = await drizzle
      .select()
      .from(emailVerificationTokens)
      .where(eq(emailVerificationTokens.tokenHash, tokenHash))
      .limit(1);
    return token ? mapEmailVerificationTokenRow(token) : null;
  }

  async markEmailVerificationTokenUsed(tokenHash: string): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle
      .update(emailVerificationTokens)
      .set({ usedAt: new Date() })
      .where(eq(emailVerificationTokens.tokenHash, tokenHash));
  }

  async markEmailVerified(userId: string): Promise<void> {
    const drizzle = getDrizzleClient();
    await drizzle.update(users).set({ emailVerifiedAt: new Date(), updatedAt: new Date() }).where(eq(users.id, userId));
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
    await drizzle.delete(passwordResetTokens);
    await drizzle.delete(emailVerificationTokens);
    await drizzle.delete(users);
  }
}

class InMemoryDatabase implements DatabaseClient {
  private users = new Map<string, DatabaseUser>();
  private usersByEmail = new Map<string, string>();
  private sessions = new Map<string, SessionRecord>();
  private passwordResetTokens = new Map<string, PasswordResetTokenRecord>();
  private emailVerificationTokens = new Map<string, EmailVerificationTokenRecord>();
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

  async createUser(user: Omit<DatabaseUser, 'id' | 'createdAt' | 'updatedAt' | 'emailVerifiedAt'>): Promise<DatabaseUser> {
    const now = new Date();
    const created: DatabaseUser = {
      ...user,
      id: crypto.randomUUID(),
      email: normalizeEmail(user.email),
      emailVerifiedAt: null,
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
    if (!current || current.revokedAt) {
      throw new Error('Session was already rotated or revoked');
    }

    current.revokedAt = new Date();
    current.replacedBySessionId = input.replacement.id;
    current.updatedAt = new Date();
    this.sessions.set(current.id, current);

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

  async revokeAllSessionsForUser(userId: string): Promise<number> {
    let revoked = 0;
    for (const session of this.sessions.values()) {
      if (session.userId === userId && !session.revokedAt) {
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

  async createPasswordResetToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void> {
    this.passwordResetTokens.set(tokenHash, {
      tokenHash,
      userId,
      expiresAt,
      usedAt: null,
      createdAt: new Date(),
    });
  }

  async findPasswordResetToken(tokenHash: string): Promise<PasswordResetTokenRecord | null> {
    return this.passwordResetTokens.get(tokenHash) ?? null;
  }

  async markPasswordResetTokenUsed(tokenHash: string): Promise<void> {
    const token = this.passwordResetTokens.get(tokenHash);
    if (!token) {
      return;
    }
    token.usedAt = new Date();
    this.passwordResetTokens.set(tokenHash, token);
  }

  async createEmailVerificationToken(userId: string, tokenHash: string, expiresAt: Date): Promise<void> {
    this.emailVerificationTokens.set(tokenHash, {
      tokenHash,
      userId,
      expiresAt,
      usedAt: null,
      createdAt: new Date(),
    });
  }

  async findEmailVerificationToken(tokenHash: string): Promise<EmailVerificationTokenRecord | null> {
    return this.emailVerificationTokens.get(tokenHash) ?? null;
  }

  async markEmailVerificationTokenUsed(tokenHash: string): Promise<void> {
    const token = this.emailVerificationTokens.get(tokenHash);
    if (!token) {
      return;
    }
    token.usedAt = new Date();
    this.emailVerificationTokens.set(tokenHash, token);
  }

  async markEmailVerified(userId: string): Promise<void> {
    const user = this.users.get(userId);
    if (!user) {
      return;
    }
    user.emailVerifiedAt = new Date();
    user.updatedAt = new Date();
    this.users.set(user.id, user);
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
    this.passwordResetTokens.clear();
    this.emailVerificationTokens.clear();
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
    emailVerifiedAt: timestamp('email_verified_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    emailUniqueIdx: uniqueIndex('users_email_unique_idx').on(table.email),
  })
);

export const passwordResetTokens = pgTable(
  'password_reset_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userIdx: index('password_reset_tokens_user_idx').on(table.userId),
    expiresAtIdx: index('password_reset_tokens_expires_at_idx').on(table.expiresAt),
  })
);

export const emailVerificationTokens = pgTable(
  'email_verification_tokens',
  {
    tokenHash: text('token_hash').primaryKey(),
    userId: text('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    usedAt: timestamp('used_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  },
  (table) => ({
    userIdx: index('email_verification_tokens_user_idx').on(table.userId),
    expiresAtIdx: index('email_verification_tokens_expires_at_idx').on(table.expiresAt),
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
export type PasswordResetTokenRow = typeof passwordResetTokens.$inferSelect;
export type EmailVerificationTokenRow = typeof emailVerificationTokens.$inferSelect;
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
    typeof payload.name !== 'string' ||
    typeof payload.sid !== 'string'
  ) {
    throw new AuthenticationError('Invalid token payload');
  }

  return {
    id: payload.sub,
    email: payload.email,
    name: payload.name,
    role: (payload.role as User['role']) || 'user',
    status: (payload.status as User['status']) || 'active',
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

export function requireVerified(user: User): void {
  if (!user.emailVerifiedAt) {
    throw new AuthorizationError('Email verification required');
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
  for (const [key, record] of inMemoryStore.entries()) {
    if (now > record.resetTime) {
      inMemoryStore.delete(key);
    }
  }

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

## File: lib/types/index.ts
````typescript
export interface User {
  id: string;
  email: string;
  name: string;
  role: 'user' | 'admin' | 'superadmin';
  status: 'active' | 'inactive' | 'suspended';
  emailVerifiedAt?: Date | null;
  createdAt?: Date;
  updatedAt?: Date;
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
  role: z.enum(['user', 'admin', 'superadmin']).optional(),
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
docker compose up -d
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

## File: README.md
````markdown
# SwissKnife

SwissKnife is a backend-first Next.js 15 starter for production-ready API foundations: authentication, user/session management, and adapter-driven infrastructure integrations that can run with strict production dependencies or local in-memory fallbacks.

![Next.js 15](https://img.shields.io/badge/Next.js-15-black) ![Postgres](https://img.shields.io/badge/Postgres-16-blue) ![Redis](https://img.shields.io/badge/Redis-7-red) ![Drizzle](https://img.shields.io/badge/Drizzle-ORM-1f9d55)

## Quick start

```bash
git clone <your-fork-or-repo-url>
cd SwissKnife_Dev
corepack pnpm install
cp .env.example .env.local
corepack pnpm db:migrate
corepack pnpm dev
```

## Architecture diagram

```text
Request
  -> Middleware (rate-limit, auth)
  -> Route (App Router handler)
  -> Module (domain logic)
  -> Adapter (interface implementation)
  -> [Postgres | Redis | S3 | Inngest | Resend]
```

## Module map

| Module | What it does | Prod adapter | Dev adapter |
|---|---|---|---|
| Auth | Register/login/refresh/logout, token/session lifecycle | Postgres session repo + Redis-backed rate limit | In-memory db/rate-limit via ALLOW_IN_MEMORY_* flags |
| Users | User CRUD + role-aware authorization checks | Postgres users repo | In-memory users repo |
| Health | Liveness/readiness with dependency checks | Postgres + Redis health probes | In-memory-ready checks when enabled |
| Observability | Logging/monitoring hooks and error reporting surfaces | Sentry/OTEL providers when configured | No-op/minimal local logging defaults |
| Platform Integrations | Shared infra clients and adapters | Redis, (extensible for S3/Inngest/Resend) | Fallback adapters for local development/testing |
````

## File: repomix.config.ts
````typescript
import { defineConfig } from 'repomix';

export default defineConfig({
  ignore: {
    customPatterns: [
      '**/node_modules/**',
      '**/.next/**',
      '**/dist/**',
      '**/build/**',
      'tsconfig.tsbuildinfo',
      '*.lock',
      'pnpm-lock.yaml',
      'package-lock.json',
      '.git/**',
      '.env.local',
      '.env.production',
      '**/*.log',
    ],
  },
  include: [
    'app/**/*.{ts,tsx,js,jsx,css}',
    'lib/**/*.{ts,tsx,js,jsx}',
    'tests/**/*.{ts,tsx,js,jsx}',
    'scripts/**/*.{ts,tsx,js,jsx,mjs}',
    'drizzle/**/*.{ts,json,sql}',
    'decisions/**/*.md',
    'docs/**/*.md',
    '*.config.{ts,js,cjs,mjs}',
    '*.json',
    '*.md',
    '.env.example',
    'docker-compose.yml',
  ],
  output: {
    style: 'markdown',
    filePath: 'repomix-output.md',
  },
});
````

## File: tests/api/auth.test.ts
````typescript
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
````

## File: tests/api/users.test.ts
````typescript
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { db, resetMockDatabase } from '@/lib/db/client';
import { signToken } from '@/lib/auth/jwt';
import { resetRateLimitStore } from '@/lib/middleware/rate-limit';
import crypto from 'crypto';

function createJsonRequest(url: string, method: 'GET' | 'POST' | 'PATCH' | 'DELETE', body?: Record<string, unknown>, token?: string) {
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
      createJsonRequest(`http://localhost/api/users/${user.id}`, 'PATCH', { name: 'x' }, token),
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

  it('returns the real target user name for GET /api/users/:id', async () => {
    const admin = await registerUser('admin-get-name@example.com', 'Admin Name', 'StrongPassword123!');
    const member = await registerUser('member-get-name@example.com', 'Real Person Name', 'StrongPassword123!');
    await db.updateUser(admin.id, { role: 'admin' });
    const token = await createAccessToken(admin.id);
    const { GET: getUserById } = await import('@/app/api/users/[id]/route');

    const response = await getUserById(createJsonRequest(`http://localhost/api/users/${member.id}`, 'GET', undefined, token), {
      params: Promise.resolve({ id: member.id }),
    });
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(payload.data.name).toBe('Real Person Name');
    expect(payload.data.name).not.toBe('User');
  });

  it('allows admin to promote a user to superadmin', async () => {
    const admin = await registerUser('admin-promote@example.com', 'Admin Promote', 'StrongPassword123!');
    const member = await registerUser('member-promote@example.com', 'Member Promote', 'StrongPassword123!');
    await db.updateUser(admin.id, { role: 'admin' });
    const adminToken = await createAccessToken(admin.id);
    const { PATCH: patchUser } = await import('@/app/api/users/[id]/route');

    const response = await patchUser(
      createJsonRequest(`http://localhost/api/users/${member.id}`, 'PATCH', { role: 'superadmin' }, adminToken),
      { params: Promise.resolve({ id: member.id }) }
    );
    const payload = await response.json();

    expect(response.status).toBe(200);
    expect(payload.data.role).toBe('superadmin');
  });

  it('writes an audit log with correct actor and target on DELETE /api/users/:id', async () => {
    const admin = await registerUser('admin-delete@example.com', 'Admin Delete', 'StrongPassword123!');
    const member = await registerUser('member-delete@example.com', 'Member Delete', 'StrongPassword123!');
    await db.updateUser(admin.id, { role: 'admin' });
    const adminToken = await createAccessToken(admin.id);
    const { DELETE: deleteUser } = await import('@/app/api/users/[id]/route');

    const auditSpy = vi.spyOn(db, 'createAuditLog');
    const response = await deleteUser(
      createJsonRequest(`http://localhost/api/users/${member.id}`, 'DELETE', undefined, adminToken),
      { params: Promise.resolve({ id: member.id }) }
    );

    expect(response.status).toBe(200);
    expect(auditSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: member.id,
        actorUserId: admin.id,
        eventType: 'users.deleted',
      })
    );
  });
});
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
    "test:unit": "vitest run --maxWorkers=1 tests/api tests/utils",
    "test:integration": "vitest run tests/integration",
    "type-check": "next typegen && tsc --noEmit",
    "verify": "npm run type-check && npm run lint && npm run test:unit && npm run build:verify",
    "db:generate": "drizzle-kit generate",
    "db:migrate": "drizzle-kit migrate",
    "db:check": "drizzle-kit check",
    "seed": "node scripts/seed.mjs",
    "db:reset": "node scripts/db-reset.mjs",
    "format": "prettier --write .",
    "repomix": "repomix"
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
