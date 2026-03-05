# Next.js 16 World-Class Baseline Scope (App Router)

This document defines a practical, production-ready baseline for evolving this codebase into a "10/10" starter for real-world teams.

## Goals

- Provide a **minimal-reinvention** architecture.
- Set **must-have** standards for security, reliability, and DX.
- Keep implementation scope realistic for phased delivery.

## Current Snapshot (from this repo)

Strengths already present:
- App Router route handlers are structured with validation, logging, and error normalization.
- Auth + RBAC concepts already exist.
- API docs and admin UI exist as a developer onboarding aid.

Gaps to close:
- In-memory database and rate limiter are not production-safe for multi-instance deployments.
- Tooling is not fully green (TypeScript/lint dependency gaps).
- Documentation/setup consistency can be improved.

---

## Architecture Baseline (Next.js 16)

### 1) Runtime & rendering strategy
- Default to **Server Components** for data-heavy UI.
- Use Client Components only for interactive islands.
- Use Route Handlers for backend APIs and server-side orchestration.
- Adopt explicit caching rules per route (`force-cache`, `no-store`, revalidation windows).

### 2) Domain-oriented module layout
Keep App Router pages thin and move logic to domain modules.

Suggested structure:

```txt
app/
  (marketing)/
  (app)/
  api/
    auth/
    users/
lib/
  domain/
    users/
      service.ts
      repository.ts
      policy.ts
      schema.ts
    auth/
      service.ts
      policy.ts
      schema.ts
  platform/
    db/
    cache/
    queue/
    telemetry/
  shared/
    errors/
    response/
    validation/
```

### 3) API contract standard
- Keep a single response envelope style for success/error.
- Generate OpenAPI from source-of-truth schemas (Zod).
- Add contract tests to prevent drift.

---

## What to Use vs What Not to Rebuild

## Use proven building blocks
- Auth/session: Auth.js or managed auth (Clerk/Supabase/Auth0) unless deep custom requirements.
- DB: Postgres + Prisma or Drizzle.
- Rate limiting: Redis/Upstash-backed distributed limiter.
- Background jobs: queue provider (e.g., Upstash QStash / Cloud Tasks / BullMQ).
- Observability: OpenTelemetry + Sentry/Datadog.

## Avoid reinventing
- Custom crypto/session token stores without threat modeling.
- Homegrown distributed rate-limiting.
- Ad-hoc migrations or SQL runbooks without tooling.
- Manual production incident workflows without instrumentation.

---

## Security Baseline (Required)

- Secure cookies for web auth flows (`httpOnly`, `secure`, `sameSite`).
- CSP, HSTS, X-Content-Type-Options, Referrer-Policy.
- Input validation on every external boundary.
- Password policy + reset flow + email verification.
- Optional MFA/passkeys for admin users.
- Secret rotation playbook and key versioning.
- Dependency scanning + SAST in CI.

### Authorization baseline
- Keep RBAC, but add policy checks in domain layer (not UI-only).
- Add audit logs for admin/security-sensitive actions.

---

## Data & Persistence Baseline

- Move to durable Postgres storage.
- Add migration pipeline (dev/preview/prod).
- Add unique constraints and critical indexes.
- Include idempotency keys for write endpoints where retries can happen.
- Add soft-delete or archival strategy for user/admin data.

---

## Reliability & Operations Baseline

### Observability
- Structured logs with request IDs and user IDs (when authenticated).
- Distributed traces across route handlers and DB calls.
- RED metrics per endpoint (rate/errors/duration).
- Error budget + SLO draft for critical endpoints.

### Runtime hardening
- Health endpoints split into liveness/readiness.
- Graceful failure paths for DB/cache/queue outages.
- Retry policies with backoff and dead-letter queue for jobs.

---

## Performance Baseline

- P95 latency budget per route category (auth/read/write).
- Query optimization + pagination limits + index review.
- Bundle analysis and client JS budget for interactive routes.
- Caching plan:
  - Request cache for stable reads.
  - Edge cache for public content.
  - Invalidation strategy for mutable resources.

---

## Quality Baseline (CI/CD)

Required merge gates:
- `type-check`
- `lint`
- `test:unit`
- `test:integration`
- `build`
- security scan (dependencies)

Release flow:
- Preview deployments on PR.
- Database migration checks on preview.
- Post-deploy smoke tests.
- Rollback instructions documented.

---

## Testing Strategy (baseline standard)

- Unit tests: pure domain/service/validation logic.
- Integration tests: route handlers + DB + auth checks.
- E2E tests: critical user journeys (register/login/admin user lifecycle).
- Contract tests: ensure API response format remains stable.

Target confidence:
- 100% of critical auth paths covered by integration/E2E.
- Load smoke for login/users list endpoints.

---

## Next.js 16 Migration/Readiness Checklist

- Replace deprecated lint integrations with ESLint CLI workflow.
- Review all Server/Client component boundaries.
- Confirm route handler runtime targets (Node vs Edge) per endpoint.
- Add instrumentation hook compatible with current Next runtime guidance.
- Validate cache tags/revalidation for data paths.

---

## Phased Execution Plan

## Phase 1 (Foundation, 1-2 weeks)
- Fix type/lint green baseline.
- Introduce Postgres + ORM with initial migrations.
- Replace in-memory rate limiter with Redis-backed limiter.
- Add CI required checks.

**Exit criteria**
- All checks green on PRs.
- No in-memory-only production path for auth/users/rate limits.

## Phase 2 (Security + Ops, 1-2 weeks)
- Harden auth/session flows and account recovery.
- Add observability stack (logs/traces/errors).
- Add audit logs for privileged actions.

**Exit criteria**
- Security baseline checklist complete.
- Dashboards + alerts for core APIs active.

## Phase 3 (Scale + DX, 1-2 weeks)
- Add contract tests and performance budgets.
- Improve generators/templates for new modules.
- Publish ADRs and runbook updates.

**Exit criteria**
- New endpoints follow template automatically.
- Team onboarding path is reproducible in <30 minutes.

---

## Practical "Do/Don't" for this codebase

### Do
- Keep route handlers thin.
- Keep validation schemas close to domain modules.
- Centralize error typing/serialization.
- Prefer managed/proven infra for auth/session/rate limit.

### Don't
- Expand mock/in-memory implementations for production pathways.
- Put authorization checks only in UI.
- Couple response formatting to page components.
- Add new endpoints without tests and observability hooks.

---

## Definition of Done for "10/10 baseline"

A release qualifies when:
1. Security baseline is complete and validated.
2. CI/CD gates prevent regressions.
3. Persistence and rate-limiting are distributed and durable.
4. Core flows are covered by integration + E2E tests.
5. Incidents are diagnosable within minutes via logs/traces/alerts.
6. New team members can bootstrap and ship a safe endpoint quickly.


## Router/Framework Patterns Worth Borrowing

Even while staying on Next.js App Router, borrow proven ideas:

- **Remix-style mutations**: co-locate mutation handling with strong server validation and predictable error surfaces.
- **Fastify/Nest API discipline**: explicit DTO/schema contracts and lifecycle hooks for logging/metrics.
- **Rails/Laravel conventions**: batteries-included runbooks, migrations, and one-command onboarding.

Takeaway: keep Next.js for UI/platform fit, but adopt stronger backend conventions where helpful.
