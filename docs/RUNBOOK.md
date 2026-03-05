# Runbook

## Local startup

1. `corepack pnpm install`
2. `cp .env.example .env.local`
3. `corepack pnpm db:migrate`
4. `corepack pnpm dev`

## Pre-merge checks

1. `corepack pnpm test:unit`
2. `corepack pnpm db:migrate`
3. `corepack pnpm test:integration`

## Production readiness

- Configure required envs: `JWT_SECRET`, `REFRESH_TOKEN_PEPPER`, `DATABASE_URL`.
- Configure Redis credentials unless intentionally using in-memory mode outside production.
- Verify health endpoints:
  - `/api/health/live`
  - `/api/health/ready`

## Incident notes

- DB outage: restore database connectivity first, then re-run readiness checks.
- Redis outage: restore Redis/upstream availability, then re-check auth-related paths.
- Suspected token compromise: rotate secrets and revoke sessions.
