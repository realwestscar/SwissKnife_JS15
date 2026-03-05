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
