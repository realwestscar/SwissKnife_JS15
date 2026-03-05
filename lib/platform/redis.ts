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
