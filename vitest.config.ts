import { defineConfig } from 'vitest/config';
import tsconfigPaths from 'vite-tsconfig-paths';

export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    env: {
      NODE_ENV: 'test',
      VERCEL_ENV: 'development',
      JWT_SECRET: '12345678901234567890123456789012',
      JWT_EXPIRY: '15m',
      JWT_REFRESH_EXPIRY: '7d',
      RATE_LIMIT_ENABLED: 'true',
      RATE_LIMIT_WINDOW_MS: '3600000',
      RATE_LIMIT_MAX_REQUESTS: '100',
    },
  },
});
