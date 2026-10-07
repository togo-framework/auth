# Changelog

## Unreleased (auth#6)

### Security
- Strict session revalidation (base driver, on by default, no flag): every
  authenticated request loads the account; a deleted account is `401` and the
  identity's roles and permissions come from the database. This makes
  `RequireRole`, `RequirePermission` and all claims consumers
  database-authoritative. It applies to the base driver only; revoked tokens stay
  refused; there is no disabled state. Personal access tokens revalidate the
  owner's existence only.
- Reset-link redemption and admin set-password are one transaction with a
  compare-and-set on the roles value judged non-administrator; a promotion in
  between is refused, the token stays burned, and `auth.credential_refused` is
  emitted (F11, F11c). The pool pre-check is removed.
- Per-field sticky provenance of identity writes (`auth_account_state`); promoting
  an account whose email or password was set by another administrator returns
  `409 identity_set_by_other_admin` unless the request carries
  `accept_identity_set_by_other` (F12).
- Impersonation and magic-link sessions end when the target becomes an
  administrator (F13).
- Deleting an administrator emits `auth.admin_cross_control` (flag on) and removes
  the account's provenance row.
- Admin writes re-check, inside the transaction, that the caller is still an
  administrator.

### Added
- Events `auth.admin_promoted`, `auth.admin_demoted`, `auth.credential_refused`.
- Startup warning when the retired `AUTH_IMPERSONATE_ADMINS` is set.
- Table `auth_account_state` (created with `CREATE TABLE IF NOT EXISTS`; `users` is
  not altered).

### Changed
- `Verify(token)` performs the database revalidation (via `VerifyContext`); prefer
  `VerifyContext` with the request context.
- The exported `SetPassword` keeps its signature, writes no provenance and is for
  trusted callers.
