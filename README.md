# auth

The togo base **auth** provider: JWT token auth, bcrypt passwords, a self-contained
users store (via the ORM), multi-guard, roles + permissions (RBAC), middleware, and
`/api/auth` routes. Default driver for the framework; Supabase/Firebase/OAuth/WorkOS
ship as driver plugins that depend on this package.

```bash
togo install togo-framework/auth
```
