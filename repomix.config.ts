import { defineConfig } from 'repomix';

export default defineConfig({
  // Exclude build artifacts and large files
  exclude: [
    '**/node_modules/**',
    '**/.next/**',
    '**/dist/**',
    '**/build/**',
    'tsconfig.tsbuildinfo',
    '*.lock',
    'pnpm-lock.yaml',
    'package-lock.json',
    '.git/**',
    '.env*',
    '**/*.log',
  ],
  // Include only source files
  include: [
    'app/**/*.{ts,tsx,js,jsx}',
    'lib/**/*.{ts,tsx,js,jsx}',
    'tests/**/*.{ts,tsx,js,jsx}',
    'scripts/**/*.{ts,tsx,js,jsx}',
    'drizzle/**/*.{ts,json,sql}',
    'docs/**/*.md',
    '*.config.{ts,js,cjs,mjs}',
    '*.json',
    '*.md',
  ],
  output: {
    style: 'markdown',
    filePath: 'repomix-output.md',
  },
});
