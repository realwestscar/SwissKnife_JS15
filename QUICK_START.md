# SwissKnife Quick Start

## 1) Install
```bash
corepack enable
corepack pnpm install
```

## 2) Configure
```bash
cp .env.example .env.local
```

## 3) Run
```bash
docker compose up -d
corepack pnpm db:migrate
corepack pnpm dev
```

## 4) Verify
```bash
corepack pnpm verify
```

If `JWT_SECRET` is not exported in your shell, `verify` uses a temporary value for the build check only. Runtime startup still requires a real `JWT_SECRET` (32+ chars).
If `REFRESH_TOKEN_PEPPER` is not set, startup fails. Set required values in `.env.local`.

## Local URLs
- Home: `http://localhost:3000`
- API base: `http://localhost:3000/api`

## API Smoke Tests
Register:
```bash
curl -X POST http://localhost:3000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "name": "Test User",
    "password": "TestPassword123!"
  }'
```

Login:
```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPassword123!"
  }'
```

## Core Files
- `app/page.tsx` - minimal starter landing page
- `app/api/auth/register/route.ts` - register endpoint
- `app/api/auth/login/route.ts` - login endpoint
- `app/api/users/route.ts` - list users (admin roles)
- `app/api/users/[id]/route.ts` - user CRUD by id
- `lib/db/client.ts` - Postgres/Drizzle repository adapter
- `lib/middleware/auth.ts` - auth and role checks
- `lib/middleware/rate-limit.ts` - request limiter
- `lib/utils/response.ts` - API response envelope

## Common Commands
```bash
corepack pnpm dev
corepack pnpm type-check
corepack pnpm lint
corepack pnpm test
corepack pnpm build
corepack pnpm verify
```
