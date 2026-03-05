import { defineConfig } from 'repomix';

export default defineConfig({
  ignore: {
    customPatterns: [
      '**/node_modules/**',
      '**/.next/**',
      '**/dist/**',
      '**/build/**',
      'tsconfig.tsbuildinfo',
      '*.lock',
      'pnpm-lock.yaml',
      'package-lock.json',
      '.git/**',
      '.env.local',
      '.env.production',
      '**/*.log',
    ],
  },
  include: [
    'app/**/*.{ts,tsx,js,jsx,css}',
    'lib/**/*.{ts,tsx,js,jsx}',
    'tests/**/*.{ts,tsx,js,jsx}',
    'scripts/**/*.{ts,tsx,js,jsx,mjs}',
    'drizzle/**/*.{ts,json,sql}',
    'decisions/**/*.md',
    'docs/**/*.md',
    '*.config.{ts,js,cjs,mjs}',
    '*.json',
    '*.md',
    '.env.example',
    'docker-compose.yml',
  ],
  output: {
    style: 'markdown',
    filePath: 'repomix-output.md',
  },
});
