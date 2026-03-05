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
