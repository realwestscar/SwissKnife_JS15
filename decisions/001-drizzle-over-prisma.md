# 001: Use Drizzle Over Prisma

## Status
Accepted

## Decision
Use Drizzle ORM as the default database access layer.

## Why
- SQL-first migrations are easy to inspect in code review.
- Tight TypeScript inference without generated runtime clients.
- Works cleanly with adapter-based architecture.

## Consequences
- Team writes more explicit SQL-aware schema/migration code.
- Migration discipline stays in-repo via `drizzle/*.sql`.
