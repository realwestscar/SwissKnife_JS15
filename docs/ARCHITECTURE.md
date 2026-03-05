# Architecture

SwissKnife follows a thin-route, module-first architecture:

```text
Request
  -> Middleware (rate-limit, auth)
  -> Route handler (App Router)
  -> Module/service logic
  -> Adapter
  -> Infrastructure (Postgres, Redis, optional S3/Inngest/Resend)
```

## What is true now

- Route handlers are in `app/api/**` and should stay thin.
- Environment and adapter guardrails are centralized in `lib/config/env.ts`.
- Auth/session behavior lives in `lib/auth/*` with rotation + reuse detection.
- Persistence is implemented with Drizzle/Postgres in `lib/db/*`.
- Rate limiting is implemented through Redis adapter paths in `lib/platform/*` and middleware.
- Response and error envelopes are standardized via utility helpers.
