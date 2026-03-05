# 002: Use jose For JWT

## Status
Accepted

## Decision
Use `jose` for JWT signing and verification.

## Why
- Standards-compliant and security-focused implementation.
- Clear APIs for signing, verification, and claim handling.
- Better long-term maintenance than ad hoc token utilities.

## Consequences
- Token claim contracts must stay explicit and tested.
- Auth middleware must enforce token type and required claims.