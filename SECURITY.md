# Security policy — togo auth

Auth is the project's primary security boundary. This package is built to an
enterprise baseline and scanned on every push (`govulncheck` + `gosec`).

## Hardening in place
- **JWT**: HS256 only (alg-confusion rejected), expiry **required**, issuer pinned
  (`togo`), `iat`/`nbf` set. Forged-secret, expired, unexpiring, and `alg=none`
  tokens are rejected (see `auth_test.go`).
- **Secrets**: fail-closed in production — `AUTH_SECRET` (>= 32 bytes) is required;
  dev generates an ephemeral random secret (no hardcoded credential).
- **Passwords**: bcrypt (cost 10), min length policy (`AUTH_MIN_PASSWORD`, default 8),
  72-byte cap enforced. **Constant-time login** (dummy-hash compare on unknown email)
  prevents user enumeration. Registration returns generic errors (no enumeration).
- **Brute force**: per-IP rate limiting on login/register (10 / 5 min).
- **CSRF**: double-submit cookie + `X-CSRF-Token` for cookie-authed mutations
  (bearer/API requests are exempt).
- **CORS**: credential-aware, allowlisted via `CORS_ORIGINS` (default: same-origin).
- **Sessions / SSR**: `HttpOnly` + `SameSite=Lax` session cookie (`Secure` in prod,
  via `COOKIE_SECURE`), token TTL (`AUTH_TTL_HOURS`), real logout that clears it.
  Token is read from the bearer header **or** the session cookie (SSR-friendly).
- **SQL injection**: the ORM parameterizes values and validates column/operator/
  ORDER BY identifiers against an allowlist.
- **RBAC / multi-guard**: roles + permissions on the identity; `RequireRole` /
  `RequirePermission` middleware; named guards.

## Configuration
`AUTH_SECRET`, `AUTH_DRIVER` (base|supabase), `AUTH_TTL_HOURS`, `AUTH_MIN_PASSWORD`,
`CORS_ORIGINS`, `COOKIE_SECURE`, `APP_ENV`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`.

## Reporting
Report vulnerabilities privately via a GitHub security advisory on this repo.
