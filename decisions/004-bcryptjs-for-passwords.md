# 004: Use bcryptjs For Passwords

## Status
Accepted

## Decision
Use `bcryptjs` for password hashing and verification.

## Why
- Proven adaptive hashing algorithm for password storage.
- Works in Node runtimes without external native setup.
- Existing code and tests already depend on bcrypt semantics.

## Consequences
- Cost factor tuning is required as hardware changes.
- Hash/compare calls must remain on trusted server paths only.