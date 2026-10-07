<!-- togo-header -->
<div align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/togo-mark-dark.svg" /><img src=".github/assets/togo-mark.svg" alt="ToGO" height="64" /></picture>
  <h1>togo-framework/auth</h1>
  <p>
    <a href="https://to-go.dev/marketplace"><img src="https://img.shields.io/badge/marketplace-to--go.dev-1F8A99" alt="marketplace" /></a>
    <a href="https://pkg.go.dev/github.com/togo-framework/auth"><img src="https://pkg.go.dev/badge/github.com/togo-framework/auth.svg" alt="pkg.go.dev" /></a>
    <img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT" />
  </p>
  <p><strong>Part of the <a href="https://to-go.dev">togo</a> framework.</strong></p>
</div>

## Install

```bash
togo install togo-framework/auth
```

<!-- /togo-header -->

<!-- togo-brand -->
<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/togo-mark-dark.svg" /><img src=".github/assets/togo-mark.svg" alt="ToGO" width="96" /></picture>
</p>
<h1 align="center">auth</h1>
<p align="center"><sub>part of the <a href="https://github.com/togo-framework">togo-framework</a> — the full-stack Go + React framework</sub></p>

The togo base **auth** provider: JWT token auth, bcrypt passwords, a self-contained
users store (via the ORM), multi-guard, roles + permissions (RBAC), middleware, and
`/api/auth` routes. Default driver for the framework; Supabase/Firebase/OAuth/WorkOS
ship as driver plugins that depend on this package.

```bash
togo install togo-framework/auth
```


## Admin user management

Mounted at `/api/auth/admin/*` for the built-in driver (`AUTH_DRIVER=base`). All
routes require the `admin` role, re-checked against the database on every request
(401 anonymous, 403 non-admin). Cookie-authenticated writes need `X-CSRF-Token`
(from `GET /api/auth/csrf`); bearer requests are exempt.

| Route | Body | Response |
|---|---|---|
| `GET /users?q=&limit=&offset=` | | `[{id,email,roles[],permissions[],created_at}]` (limit default 100, max 500) |
| `POST /users` | `{email, password?, roles?, permissions?}` | `201 {user}` |
| `GET /users/{id}` | | user |
| `PATCH /users/{id}` | `{email?, roles?, permissions?}` | user |
| `DELETE /users/{id}` | | `{deleted:true,id}` |
| `POST /users/{id}/impersonate` | | `{token, identity{..., impersonator}, expires_at}` |
| `POST /users/{id}/reset-password` | `{password?}` | `{reset:true}` or `{link, emailed:false, expires_at}` |
| `POST /users/{id}/magic-link` | | `{link, emailed:false, expires_at}` |

Also: `GET /api/auth/magic?token=` (redeems a magic link, 302 to
`AUTH_POST_LOGIN_URL`), `POST /api/auth/impersonation/stop` (ends an impersonation),
and `GET /api/auth/me`, which includes `impersonator` (the admin's id) while impersonating.
Events: `auth.user_created|updated|deleted|impersonated`, `auth.impersonation_ended`,
`auth.magic_link_issued`, `auth.admin_reset_link_issued`. Payloads name the actor and
never carry a token or link. See `SECURITY.md` for the policy.

Rules for acting on another administrator: impersonate, `reset-password`, `magic-link`
and changing their `email`, `roles` or `permissions` (PATCH) are all refused with 403 by
default. `AUTH_ADMIN_CROSS_CONTROL=true` is the single, explicitly privileged opt-in that
relaxes every one of these admin-target restrictions (it is the only such flag; it is
configuration only and cannot be granted through the API). Each cross-admin operation done
under it emits `auth.admin_cross_control` (`actor_id`, `target_id`, `operation`, `policy`). Always allowed: self-edits (including self-demotion, subject to the
last-administrator rule), promoting a non-admin to admin, and deleting another admin (no session
is created as them; the last administrator is always protected). These are audited:
`auth.user_updated` carries `actor_id`, `target_id` and the changed field names (no values);
`auth.user_deleted` carries `actor_id` and `target_id`. Reset and magic links an admin issued
for an ordinary user stop working if that user has since become an admin (unless the opt-in is
on); self-service forgot-password tokens are unaffected. Request bodies reject unknown fields. A magic link redeemed for a user starts a session that
names the issuing admin (`impersonator`, `act` claim, `auth.login` event, plus
`auth.magic_link_redeemed`) and lasts as long as an impersonation.

Config: `AUTH_PUBLIC_URL`/`APP_URL` (link base), `AUTH_RESET_PATH` (default `/reset-password`),
`AUTH_POST_LOGIN_URL`, `AUTH_IMPERSONATION_TTL_MINUTES` (default 30, max 480),
`AUTH_ADMIN_CROSS_CONTROL` (default off; the only switch for cross-admin control).

Token verification: `Verify(token)` now delegates to `VerifyContext(ctx, token)`, which also
enforces revocation and the actor/target checks for impersonation tokens (a database lookup).
Prefer `VerifyContext` with the request context.

`auth.password_reset_requested` carries the raw reset token so a mailer can deliver it; it is
for in-process hook subscribers only and must never be logged or forwarded to an external bus.

## Sessions and the database (strict revalidation)

A token proves who the caller is. The database decides what that caller may do
now. With the built-in driver (`AUTH_DRIVER=base`) every authenticated request
loads the account by id (one primary-key read), and:

- if the account is gone, the request is `401`;
- the identity's email, roles and permissions are replaced by the stored values.

This happens in `VerifyContext` and in the personal-access-token path of
`Authenticate`/`Middleware`, so everything that consumes the identity is
database-authoritative with no change on your side: `RequireRole`,
`RequirePermission`, `IdentityFrom`, `Authenticate`, and any route that reads
claims from the context. A demoted administrator gets `403` on the very next
request, a deleted account `401`, and a promoted user's existing session carries
the admin role as soon as the database says so. An app that guards routes with
`svc.RequireRole("admin")`, `svc.Middleware` or `svc.Authenticate` is covered.
An app that parses the JWT itself (for example with its own `jwt.Parse`) is not:
use `VerifyContext`.

Details:

- Revoked impersonation and magic-link tokens (by `jti`) stay refused.
  An impersonation or magic-link session also needs its issuing administrator to
  still be an administrator, and is refused once its target is an administrator
  (unless `AUTH_ADMIN_CROSS_CONTROL=true`).
- Personal access tokens revalidate only that the owner exists. They keep their
  own abilities and are never administrators.
- There is no disabled or suspended state in this plugin, so "the account
  exists" is the whole test. `revalidate` in `auth.go` is the single place a
  future disabled or security-version check goes.
- Applies to the base driver only. With `AUTH_DRIVER=supabase` (or any external
  driver) the provider owns identity, the users table is not authoritative, and
  tokens are verified as before.
- No new configuration; no token claim or session format changes. Tokens issued
  before an upgrade keep working: their roles are simply read from the database.
- `Verify(token)` now performs the database check (it calls `VerifyContext`
  with a background context). Prefer `VerifyContext` with the request context.

## Provenance and the promotion gate

An administrator who sets an account's email or password, or who creates the
account, is recorded as the writer of that field in the side table
`auth_account_state` (created automatically; `users` is never altered). The
password written by redeeming an administrator-issued reset link is attributed to
the issuer. Provenance is sticky: the holder changing their own password does
**not** clear it.

Promoting an account to administrator (`PATCH /users/{id}` with `roles`
containing `admin`) answers **`409 Conflict`** if any field was written by someone
other than the holder and the promoting administrator:

```json
{"error":"identity_set_by_other_admin","message":"...","tainted_fields":["email"],
 "set_by":{"email":"<admin id>"},"set_at":{"email":"..."},"accept_field":"accept_identity_set_by_other"}
```

The condition is deliberate and must be surfaced, never retried silently: a UI
should show who set which field and ask the promoter to confirm. Sending the same
request with `"accept_identity_set_by_other": true` promotes, and the acceptance
applies to that one request only. It is recorded (`accepted_by`, `accepted_at`)
and audited in `auth.admin_promoted` (`tainted`, `accepted`). A promoter's own
earlier writes are exempt.

Redeeming an administrator-issued reset link and the admin set-password mode run
in one transaction that writes the password only while the account's roles are
still the value that was judged non-administrator. If the account was promoted in
between, nothing is written: a redemption commits the burn of the token, answers
the same generic `401` as any invalid link, and emits `auth.credential_refused`
(`type`, `issuer`, `target_id`); set-password answers `409`.

Promotion is judged on the provenance stored before the request. Changing the
`email` in the same request as the promotion does not clear another administrator's
email provenance (still `409`); only a write the promoter made in an earlier request
is exempt. A password set by redeeming a self-service reset token inherits the
provenance of the email the token was sent to (an administrator-issued link: the
issuer), so it counts as set by that administrator.

Reset tokens and magic links are bound to the account state they were issued
against (`auth_recovery_context`; `auth_priv_epoch` counts promotions and
demotions; both created automatically, `users` is never altered). Redemption
refuses a token, burning it and answering the generic `401`, if the email changed
(self-service tokens), or the account was promoted or demoted since (all tokens).
Tokens that predate the upgrade have no context and are refused. `SetRoles`
bumps the counter too.

New events: `auth.admin_promoted`, `auth.admin_demoted`, `auth.credential_refused`.

### Trusted-caller API

The exported Go methods (`SetPassword`, `SetRoles`, `CreateUser`, ...) are for
trusted code in your own process. They apply the password policy but do not
apply the admin-target rules above, write no provenance, and do not take the
compare-and-set. Do not expose them to request input without your own
authorization.

Startup logs a warning if the retired variable `AUTH_IMPERSONATE_ADMINS` is set:
it has no effect; the flag is `AUTH_ADMIN_CROSS_CONTROL`.

## Frontend

UI lives in the separate [dashboard](https://github.com/togo-framework/dashboard)
plugin (login/register/reset/2fa/lock/profile/dashboard), which depends on this package.


---

## 💎 Premium sponsors

togo is proudly sponsored by **ID8 Media** and **One Studio**.

<p align="center">
  <a href="https://id8media.com"><img src=".github/assets/id8media.svg" height="44" alt="ID8 Media" /></a>
  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://one-studio.co"><img src=".github/assets/one-studio.jpeg" height="44" alt="One Studio" /></a>
</p>

<!-- togo-sponsors -->
---

<div align="center">
  <h3>Premium sponsors</h3>
  <p>
    <a href="https://id8media.com"><strong>ID8 Media</strong></a> &nbsp;·&nbsp;
    <a href="https://one-studio.co"><strong>One Studio</strong></a>
  </p>
  <p><sub>Support togo — <a href="https://github.com/sponsors/fadymondy">become a sponsor</a>.</sub></p>
</div>
<!-- /togo-sponsors -->
