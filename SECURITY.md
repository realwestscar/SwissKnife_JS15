# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via your internal security/contact channel rather than opening a public issue.

Include:
- Affected area and impact
- Reproduction steps or proof of concept
- Suggested mitigation (if available)

## Security baseline

- JWT and refresh-token secrets are required in production.
- Refresh tokens are rotated and reuse is detected/revoked.
- Environment variables are validated at startup.
- Auth-related routes are rate limited.

## Operational response

- Rotate `JWT_SECRET` for global token invalidation events.
- Rotate `REFRESH_TOKEN_PEPPER` for refresh-token hash invalidation.
- Revoke active sessions when compromise is suspected.
