# SwissKnife

SwissKnife is a backend-first Next.js 15 starter for production-ready API foundations: authentication, user/session management, and adapter-driven infrastructure integrations that can run with strict production dependencies or local in-memory fallbacks.

![Next.js 15](https://img.shields.io/badge/Next.js-15-black) ![Postgres](https://img.shields.io/badge/Postgres-16-blue) ![Redis](https://img.shields.io/badge/Redis-7-red) ![Drizzle](https://img.shields.io/badge/Drizzle-ORM-1f9d55)

## Quick start

```bash
git clone <your-fork-or-repo-url>
cd SwissKnife_Dev
corepack pnpm install
cp .env.example .env.local
corepack pnpm db:migrate
corepack pnpm dev
```

## Architecture diagram

```text
Request
  -> Middleware (rate-limit, auth)
  -> Route (App Router handler)
  -> Module (domain logic)
  -> Adapter (interface implementation)
  -> [Postgres | Redis | S3 | Inngest | Resend]
```

## Module map

| Module | What it does | Prod adapter | Dev adapter |
|---|---|---|---|
| Auth | Register/login/refresh/logout, token/session lifecycle | Postgres session repo + Redis-backed rate limit | In-memory db/rate-limit via ALLOW_IN_MEMORY_* flags |
| Users | User CRUD + role-aware authorization checks | Postgres users repo | In-memory users repo |
| Health | Liveness/readiness with dependency checks | Postgres + Redis health probes | In-memory-ready checks when enabled |
| Observability | Logging/monitoring hooks and error reporting surfaces | Sentry/OTEL providers when configured | No-op/minimal local logging defaults |
| Platform Integrations | Shared infra clients and adapters | Redis, (extensible for S3/Inngest/Resend) | Fallback adapters for local development/testing |
