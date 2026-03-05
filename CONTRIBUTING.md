# Contributing

## Setup

1. `corepack pnpm install`
2. `cp .env.example .env.local`
3. `corepack pnpm db:migrate`
4. `corepack pnpm dev`

## Conventions

- Keep route handlers thin: middleware -> validation -> module/service -> response helper.
- Use canonical API envelopes for success/error responses.
- Add or update tests for behavior changes (`test:unit`, and `test:integration` when infra behavior changes).
- Prefer adapter-based implementations over direct infra calls inside route files.

## PR process

1. Branch from `main`.
2. Run:
   - `corepack pnpm test:unit`
   - `corepack pnpm db:migrate`
   - `corepack pnpm test:integration`
3. Open a PR with a concise summary, validation steps, and any migration/env impact.
