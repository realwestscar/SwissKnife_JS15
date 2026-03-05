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
