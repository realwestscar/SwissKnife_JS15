# 005: Use zod For Validation

## Status
Accepted

## Decision
Use `zod` for request boundary validation.

## Why
- Type-safe runtime validation from a single schema source.
- Clear error flattening for consistent API error payloads.
- Lightweight and already adopted across routes.

## Consequences
- All endpoints should validate input before authorization logic that depends on parsed data.
- Validation schemas are part of API contract and must be versioned with care.