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
