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

- **Admin API** (`/api/auth/admin/*`, v0.10.0): authenticated is not administrator.
  Every route re-reads the caller from the database and requires the `admin` role
  (anonymous -> 401, non-admin -> 403; a demoted admin loses access at once, API
  tokens and impersonated sessions never qualify). Writes need CSRF for cookie
  sessions. The last administrator cannot be deleted or demoted.
- **Magic / reset links**: 256-bit random token, only its SHA-256 stored, single-use
  (atomic consume), 15 min (magic) / 30 min (reset), purpose-bound, superseded by
  the next link for the account, never in events or logs. The base URL is only
  `AUTH_PUBLIC_URL` / `APP_URL`; unset means a relative path, never the Host header.
  A magic link does not bypass 2FA.
- **Impersonation**: token carries `act.sub` (the admin) + `jti`, 30 min default
  (`AUTH_IMPERSONATION_TTL_MINUTES`, max 480), audit events name actor and target,
  revocable via `POST /api/auth/impersonation/stop`, dies if the admin is demoted,
  cannot call the admin API or change the borrowed account's password/2FA/PIN/tokens.
  Impersonating another admin is refused unless `AUTH_ADMIN_CROSS_CONTROL=true`; the same
  rule covers reset-password, magic-link and changing another admin's email, roles or
  permissions (account takeover by other means, e.g. demote, change email, reset,
  re-promote). `AUTH_ADMIN_CROSS_CONTROL` is the single, config-only opt-in that relaxes all of them; each use is audited as `auth.admin_cross_control` with actor, target, operation and policy. Self-edits,
  promoting a non-admin and deleting an admin stay allowed, keep the last-admin invariant
  (enforced in a database transaction, safe across instances) and are audited with actor
  and target. Admin-issued reset and magic links are refused at redemption if the target
  has become an admin. A redeemed magic link names its
  issuing admin in the session. `Verify` delegates to `VerifyContext`, so revocation is
  enforced for every caller. `auth.password_reset_requested` carries the raw token for
  the mailer: in-process hook subscribers only; never log or forward it.

## Session revalidation and admin lifecycle (auth#6)
- **Strict revalidation (base driver).** Every authenticated request loads the account
  by id; a missing account is `401`, and the identity's email, roles and permissions
  are replaced by the database values, so `RequireRole`, `RequirePermission` and every
  other claims consumer are database-authoritative. A demoted administrator is refused
  on the next request; a deleted account's token stops working. Revoked `jti`s stay
  refused. There is no disabled state; the single hook for one is `revalidate` in
  `auth.go`. External drivers (`AUTH_DRIVER=supabase`) are not revalidated against the
  users table. Tokens issued before the upgrade need no action.
- **No takeover through a window.** Admin-issued reset redemption and admin set-password
  write the password in one transaction, conditional on the roles value that was judged
  non-administrator; a promotion that lands in between is refused (generic `401` for a
  link, burning it; `409` for set-password) and emits `auth.credential_refused`.
- **Provenance.** Email and password written by an administrator other than the holder
  are recorded per field (`auth_account_state`), accumulate (a later administrator's
  write never erases an earlier one's) and stay recorded. Promoting such an
  account returns `409 identity_set_by_other_admin` unless that request carries
  `accept_identity_set_by_other`; the acceptance is recorded and audited in
  `auth.admin_promoted`, applies to that request only and does not clear the record.
  The promoter's own earlier writes are exempt only when they are the sole writer. The
  UI must not retry it silently.
- **Self-service is not a trust source.** Its trust derives from the provenance and
  current validity of the recovery identity or credential used to perform it. A
  password set by redeeming a token sent to an email an administrator set is recorded
  as that administrator's. Promotion judges provenance as it was before the request;
  changing the email in the same request does not clear it.
- **Recovery tokens do not survive a transition.** A reset token or magic link is
  checked at redemption, inside the transaction and under the account row lock, against
  the account as it was when issued: email and who set it (self-service tokens),
  administrator status and a promote/demote counter (all tokens). A refused token is
  burned and answers the same `401` as an unknown one.
- **Act-limited sessions** (impersonation, magic link) end when the target becomes an
  administrator, unless `AUTH_ADMIN_CROSS_CONTROL=true`.
- **Exported Go API is for trusted callers**: `SetPassword` and friends skip the
  admin-target rules, provenance and compare-and-set.

## Configuration
`AUTH_SECRET`, `AUTH_DRIVER` (base|supabase), `AUTH_TTL_HOURS`, `AUTH_MIN_PASSWORD`,
`CORS_ORIGINS`, `COOKIE_SECURE`, `APP_ENV`, `SUPABASE_URL`, `SUPABASE_ANON_KEY`,
`AUTH_PUBLIC_URL` (or `APP_URL`), `AUTH_RESET_PATH`, `AUTH_POST_LOGIN_URL`,
`AUTH_IMPERSONATION_TTL_MINUTES`, `AUTH_ADMIN_CROSS_CONTROL`.

## Reporting
Report vulnerabilities privately via a GitHub security advisory on this repo.
