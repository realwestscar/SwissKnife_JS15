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
