# API Conventions

## Route shape

Keep route handlers thin and consistent:
1. Parse request metadata.
2. Apply rate-limit/auth middleware.
3. Validate input with Zod schemas.
4. Call module/service logic.
5. Return canonical response envelope.

## Response formats

- Success: `{ success: true, data, meta }`
- Error: `{ success: false, error, meta }`

`meta` includes `requestId` and timestamp, and responses include `X-Request-Id`.

## Error handling

- Validate at boundaries before business logic.
- Normalize known errors to stable error codes.
- Enforce role checks server-side only.
