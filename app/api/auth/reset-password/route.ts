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
