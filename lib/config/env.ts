import { z } from 'zod';

const baseEnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  VERCEL_ENV: z.string().default('development'),
  JWT_SECRET: z.string().optional(),
  JWT_EXPIRY: z.string().default('15m'),
  JWT_REFRESH_EXPIRY: z.string().default('7d'),
  REFRESH_TOKEN_PEPPER: z.string().optional(),
  DATABASE_URL: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  UPSTASH_REDIS_REST_URL: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  UPSTASH_REDIS_REST_TOKEN: z
    .union([z.string().min(1), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  RATE_LIMIT_ENABLED: z
    .enum(['true', 'false'])
    .default('true')
    .transform((value) => value === 'true'),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().positive().default(3_600_000),
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().positive().default(100),
  ALLOW_IN_MEMORY_SERVICES: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  ALLOW_IN_MEMORY_DB: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  ALLOW_IN_MEMORY_RATE_LIMIT: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? undefined : value === 'true')),
  SENTRY_DSN: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  OTEL_EXPORTER_OTLP_ENDPOINT: z
    .union([z.string().url(), z.literal('')])
    .optional()
    .transform((value) => (value ? value : undefined)),
  BUILD_VERIFY: z
    .enum(['true', 'false'])
    .optional()
    .transform((value) => (value === undefined ? false : value === 'true')),
});

const parsed = baseEnvSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('[env] Invalid environment variables:');
  console.error(parsed.error.flatten().fieldErrors);
  process.exit(1);
}

const data = parsed.data;
const isLikelyTestRuntime = Boolean(process.env.VITEST) || process.argv.some((arg) => arg.toLowerCase().includes('vitest'));
const isTest = data.NODE_ENV === 'test' || isLikelyTestRuntime;
const isProduction = data.NODE_ENV === 'production' || data.VERCEL_ENV === 'production';
const allowInMemoryServices = data.ALLOW_IN_MEMORY_SERVICES ?? (isTest || data.NODE_ENV === 'development');
const allowInMemoryDb = data.ALLOW_IN_MEMORY_DB ?? allowInMemoryServices;
const allowInMemoryRateLimit = data.ALLOW_IN_MEMORY_RATE_LIMIT ?? allowInMemoryServices;
const isBuildVerify = data.BUILD_VERIFY;
const resolvedJwtSecret = data.JWT_SECRET ?? (isTest ? 'test-jwt-secret-12345678901234567890' : undefined);
const resolvedRefreshPepper = data.REFRESH_TOKEN_PEPPER ?? (isTest ? 'test-refresh-pepper-123456' : undefined);

const validationErrors: string[] = [];

if (!resolvedJwtSecret || resolvedJwtSecret.length < 32) {
  validationErrors.push('JWT_SECRET must be at least 32 characters');
}

if (!resolvedRefreshPepper || resolvedRefreshPepper.length < 16) {
  validationErrors.push('REFRESH_TOKEN_PEPPER must be at least 16 characters');
}

if (!data.DATABASE_URL && !allowInMemoryDb) {
  validationErrors.push('DATABASE_URL is required unless ALLOW_IN_MEMORY_DB=true');
}

if ((!data.UPSTASH_REDIS_REST_URL || !data.UPSTASH_REDIS_REST_TOKEN) && !allowInMemoryRateLimit) {
  validationErrors.push('UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN are required unless ALLOW_IN_MEMORY_RATE_LIMIT=true');
}

if (isProduction && !isBuildVerify && (allowInMemoryServices || allowInMemoryDb || allowInMemoryRateLimit)) {
  validationErrors.push('ALLOW_IN_MEMORY_* flags cannot be true in production');
}

if (validationErrors.length > 0) {
  console.error('[env] Invalid environment variables:');
  for (const error of validationErrors) {
    console.error(` - ${error}`);
  }
  process.exit(1);
}

export const env = {
  ...data,
  JWT_SECRET: resolvedJwtSecret!,
  REFRESH_TOKEN_PEPPER: resolvedRefreshPepper!,
  ALLOW_IN_MEMORY_SERVICES: allowInMemoryServices,
  ALLOW_IN_MEMORY_DB: allowInMemoryDb,
  ALLOW_IN_MEMORY_RATE_LIMIT: allowInMemoryRateLimit,
};

export function isProductionEnvironment() {
  return isProduction;
}
