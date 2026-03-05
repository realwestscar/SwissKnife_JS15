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
