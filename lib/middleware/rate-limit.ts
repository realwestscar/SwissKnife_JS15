import { Ratelimit } from '@upstash/ratelimit';
import { env } from '@/lib/config/env';
import { getRedisClient } from '@/lib/platform/redis';
import { RateLimitError, ServiceUnavailableError } from '@/lib/utils/errors';
import { logger } from '@/lib/utils/logger';

interface RateLimitPolicy {
  windowMs?: number;
  maxRequests?: number;
  failOpen?: boolean;
}

interface InMemoryRecord {
  count: number;
  resetTime: number;
}

const inMemoryStore = new Map<string, InMemoryRecord>();
const limiterCache = new Map<string, Ratelimit>();

const shouldUseInMemoryLimiter =
  env.ALLOW_IN_MEMORY_RATE_LIMIT || !env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN;

function getWindow(windowMs: number): `${number} s` {
  return `${Math.max(1, Math.floor(windowMs / 1000))} s`;
}

function getLimiter(windowMs: number, maxRequests: number): Ratelimit {
  const key = `${windowMs}:${maxRequests}`;
  const cached = limiterCache.get(key);
  if (cached) {
    return cached;
  }

  const limiter = new Ratelimit({
    redis: getRedisClient(),
    limiter: Ratelimit.fixedWindow(maxRequests, getWindow(windowMs)),
    prefix: 'swissknife',
  });

  limiterCache.set(key, limiter);
  return limiter;
}

function checkRateLimitInMemory(identifier: string, windowMs: number, maxRequests: number) {
  const now = Date.now();
  for (const [key, record] of inMemoryStore.entries()) {
    if (now > record.resetTime) {
      inMemoryStore.delete(key);
    }
  }

  const existing = inMemoryStore.get(identifier);
  if (!existing || now > existing.resetTime) {
    inMemoryStore.set(identifier, { count: 1, resetTime: now + windowMs });
    return;
  }

  existing.count += 1;
  if (existing.count > maxRequests) {
    throw new RateLimitError(`Rate limit exceeded. Max ${maxRequests} requests per ${Math.round(windowMs / 60000)} minutes`);
  }
}

export async function checkRateLimit(identifier: string, policy: RateLimitPolicy = {}): Promise<void> {
  if (!env.RATE_LIMIT_ENABLED) {
    logger.warn('Rate limiting is disabled. Do not use this setting in production.');
    return;
  }

  const windowMs = policy.windowMs ?? env.RATE_LIMIT_WINDOW_MS;
  const maxRequests = policy.maxRequests ?? env.RATE_LIMIT_MAX_REQUESTS;
  const failOpen = policy.failOpen ?? true;

  if (shouldUseInMemoryLimiter) {
    checkRateLimitInMemory(identifier, windowMs, maxRequests);
    return;
  }

  try {
    const limiter = getLimiter(windowMs, maxRequests);
    const result = await limiter.limit(identifier);
    if (!result.success) {
      throw new RateLimitError(`Rate limit exceeded. Max ${maxRequests} requests per ${Math.round(windowMs / 60000)} minutes`);
    }
  } catch (error) {
    if (error instanceof RateLimitError) {
      throw error;
    }

    logger.error('Rate limiter dependency unavailable', {
      identifier,
      failOpen,
      error: error instanceof Error ? error.message : String(error),
      alertTag: 'rate_limit_dependency_unavailable',
    });

    if (failOpen) {
      return;
    }

    throw new ServiceUnavailableError('Rate limit service unavailable');
  }
}

export function createRateLimitMiddleware(windowMs: number = env.RATE_LIMIT_WINDOW_MS, maxRequests: number = env.RATE_LIMIT_MAX_REQUESTS, failOpen: boolean = true) {
  return async (identifier: string): Promise<void> => {
    await checkRateLimit(identifier, { windowMs, maxRequests, failOpen });
  };
}

export async function resetRateLimitStore() {
  inMemoryStore.clear();
  limiterCache.clear();
}
