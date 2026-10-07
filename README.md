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
