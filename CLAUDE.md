# CLAUDE.md

SwissKnife is a backend-first Next.js App Router template focused on secure auth and maintainable API foundations. The codebase is organized so domain modules stay stable while adapters swap between production dependencies and local/test fallbacks.

## Where things live

- **Auth logic:** `lib/auth/*` and auth routes under `app/api/auth/*`.
- **Domain modules:** route handlers in `app/api/**` and supporting services/repositories in `lib/**`.
- **Validation:** `lib/validation/schemas.ts` for request boundary schemas.

## Dual-adapter pattern (one explanation)

The app uses dependency adapters so domain behavior is consistent across environments:
- In production, adapters target real infra (Postgres, Redis, and optional external services).
- In dev/test, `ALLOW_IN_MEMORY_*` flags can route to in-memory adapters.
- Environment parsing/guardrails in `lib/config/env.ts` decide when fallbacks are legal.

## How to add a new module

1. Define the domain boundary (input schema + output shape).
2. Add/extend adapter interfaces in `lib/*` for required persistence/external calls.
3. Implement production adapter first; add in-memory/test adapter if needed.
4. Add route handlers under `app/api/<module>` that do: middleware -> validation -> module call -> response helper.
5. Add route-level tests in `tests/api` and integration coverage in `tests/integration` when infra behavior matters.

## How to add a new route

1. Create `app/api/<path>/route.ts`.
2. Parse and validate input at the boundary.
3. Apply auth/rate-limit middleware in the existing order.
4. Call module/service logic (no heavy business logic in route file).
5. Return standardized responses via response helpers and include request metadata.

## Key conventions

- **Error format:** `{ success: false, error, meta }`.
- **Response format:** `{ success: true, data, meta }`.
- **Pipeline order:** request -> rate limit/auth middleware -> validation -> module/service -> response helper.

## Files that matter (top 10)

1. `lib/config/env.ts` — env schema, validation, and in-memory fallback policy.
2. `lib/db/connection.ts` — DB adapter wiring and runtime DB mode behavior.
3. `lib/db/schema.ts` — Drizzle data model definitions.
4. `lib/auth/session-service.ts` — session lifecycle, rotation, and reuse detection.
5. `lib/middleware/auth.ts` — auth extraction and authorization helpers.
6. `lib/middleware/rate-limit.ts` — rate-limit policy and enforcement path.
7. `lib/utils/response.ts` — canonical success/error response envelope.
8. `app/api/auth/login/route.ts` — representative auth route boundary.
9. `app/api/users/route.ts` — representative protected/admin route boundary.
10. `tests/integration/production-paths.test.ts` — integration behavior expectations.
