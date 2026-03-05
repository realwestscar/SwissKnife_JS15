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
