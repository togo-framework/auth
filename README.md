# auth

The togo base **auth** provider: JWT token auth, bcrypt passwords, a self-contained
users store (via the ORM), multi-guard, roles + permissions (RBAC), middleware, and
`/api/auth` routes. Default driver for the framework; Supabase/Firebase/OAuth/WorkOS
ship as driver plugins that depend on this package.

```bash
togo install togo-framework/auth
```

## Frontend (injected)

`togo install togo-framework/auth` injects a prism-style Next.js auth suite into the
app's `web/`: **login, register, reset (OTP), two-factor (TOTP), lock (PIN), profile,
dashboard**, plus `lib/auth.ts` (CSRF-aware client) and `components/auth-card.tsx`.
Self-contained (Tailwind only) so it compiles in any togo app.
