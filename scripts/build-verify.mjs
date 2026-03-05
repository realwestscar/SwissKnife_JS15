import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const nextBin = require.resolve('next/dist/bin/next');

const env = { ...process.env };

if (!env.JWT_SECRET) {
  env.JWT_SECRET = 'verify-build-secret-123456789012345';
  console.warn('[verify] JWT_SECRET is not set; using a temporary value for local build verification only.');
}

if (!env.REFRESH_TOKEN_PEPPER) {
  env.REFRESH_TOKEN_PEPPER = 'verify-refresh-token-pepper-12345';
  console.warn('[verify] REFRESH_TOKEN_PEPPER is not set; using a temporary value for local build verification only.');
}

if (!env.ALLOW_IN_MEMORY_DB) {
  env.ALLOW_IN_MEMORY_DB = 'true';
}

if (!env.ALLOW_IN_MEMORY_RATE_LIMIT) {
  env.ALLOW_IN_MEMORY_RATE_LIMIT = 'true';
}

env.BUILD_VERIFY = 'true';

const result = spawnSync(process.execPath, [nextBin, 'build'], {
  stdio: 'inherit',
  env,
});

if (result.error) {
  console.error('[verify] Failed to run Next.js build:', result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
