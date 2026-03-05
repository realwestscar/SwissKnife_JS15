# Testing

## Commands

```bash
corepack pnpm test:unit
corepack pnpm db:migrate
corepack pnpm test:integration
```

## Current test intent

- Unit/API tests verify auth, users, validation, response envelope, and helper behavior.
- Integration tests verify production-style adapter paths and readiness behavior.

## Test authoring rules

- Place tests in `tests/**/*.test.ts`.
- Prefer route-level behavior tests for API contracts.
- Assert status code and canonical response shape.
