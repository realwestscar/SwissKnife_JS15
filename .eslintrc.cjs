module.exports = {
  root: true,
  extends: ['next/core-web-vitals', 'next/typescript'],
  ignorePatterns: ['node_modules', '.next', '.vercel', 'dist', 'next-env.d.ts'],
  rules: {
    'no-console': 'off'
  },
  overrides: [
    {
      files: ['**/*.js'],
      rules: {
        '@typescript-eslint/no-require-imports': 'off'
      }
    }
  ]
};
