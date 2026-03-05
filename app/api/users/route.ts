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
