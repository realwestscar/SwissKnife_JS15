# 003: Use Upstash For Rate Limiting

## Status
Accepted

## Decision
Use Upstash Redis as the default rate-limit backend.

## Why
- Serverless-friendly and operationally simple.
- Works with global deployments where in-memory counters fail.
- Integrates directly with `@upstash/ratelimit`.

## Consequences
- Redis dependency availability affects auth endpoints.
- `failOpen` policy must be chosen per endpoint risk.