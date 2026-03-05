# CLAUDE.md

SwissKnife is a backend-first Next.js App Router template focused on secure auth and maintainable API foundations.

## Where Things Live

- Auth logic: `lib/auth/*` and auth routes under `app/api/auth/*`
- Domain modules: route handlers in `app/api/**` and services/repositories in `lib/**`
- Validation: `lib/validation/schemas.ts`

## Key Conventions

- Error format: `{ success: false, error, meta }`
- Response format: `{ success: true, data, meta }`
- Pipeline order: request -> rate limit/auth middleware -> validation -> service -> response helper
- Update rule: update `CLAUDE.md` in the same commit as any convention change

## Worked Example: Add A Protected Endpoint

1. Add `app/api/projects/route.ts`.
2. In handler order:
   - `await checkRateLimit(...)`
   - `const user = await extractUser(request); requireAuth(user); requireRole(user, 'admin', 'superadmin')`
   - Validate body/query with zod schema
   - Call DB/service logic
   - Return `successResponse(...)`
3. Add tests under `tests/api/projects.test.ts` for:
   - missing token -> `401`
   - non-admin -> `403`
   - valid admin path -> `200`

## Worked Example: Add A Drizzle Migration

1. Update table model in `lib/db/schema.ts`.
2. Generate migration:
   - `corepack pnpm db:generate`
3. Verify SQL in `drizzle/*.sql`.
4. Apply locally:
   - `corepack pnpm db:migrate`
5. Add/adjust tests that cover the new DB behavior.

## Worked Example: Add A New Error Class

1. Add class in `lib/utils/errors.ts` extending `AppError`.
2. Set stable code/status pair (example: `new AppError('PAYMENT_REQUIRED', 402, ...)`).
3. Throw only at domain boundary, not deep utility layers unless required.
4. Add a test to confirm route returns expected `error.code` and HTTP status.

## Never Do This

- Do not bypass zod validation for request input.
- Do not return raw thrown errors directly to clients.
- Do not hardcode fallback identities (example: `name: 'User'`) in auth middleware.
- Do not use `ALLOW_IN_MEMORY_*` flags in production.
