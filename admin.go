package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
)

// Admin user management: /api/auth/admin/*.
//
// Authenticated does not mean administrator. Every route here goes through
// requireAdmin, which authenticates the caller and then re-reads the account
// from the database, so a token minted before a demotion or deletion stops
// working at once. A caller with no valid credentials gets 401; a signed-in
// user who is not an administrator gets 403. Writes also carry the plugin's
// double-submit CSRF guard (bearer requests are exempt, as everywhere else).
//
// The routes are mounted only for the built-in DB-backed driver
// (AUTH_DRIVER=base); with an external driver the users table is not the
// source of truth, so there is nothing for this API to manage.

const (
	adminRole        = "admin"
	maxAdminBody     = 64 << 10
	defaultListLimit = 100
	maxListLimit     = 500
	maxListEntries   = 32
	maxListEntryLen  = 64
)

// adminUser is the admin-facing shape of an account. Roles and permissions are
// arrays here and comma-joined TEXT in the table.
type adminUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
}

func toAdminUser(u *User) adminUser {
	roles, perms := splitCSV(u.Roles), splitCSV(u.Permissions)
	if roles == nil {
		roles = []string{}
	}
	if perms == nil {
		perms = []string{}
	}
	return adminUser{ID: u.ID, Email: u.Email, Roles: roles, Permissions: perms, CreatedAt: u.CreatedAt}
}

func isAdminUser(u *User) bool { return contains(splitCSV(u.Roles), adminRole) }

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// adminInternal logs the real error and tells the client nothing about it.
func (s *Service) adminInternal(w http.ResponseWriter, op string, err error) {
	if s.k != nil && s.k.Log != nil {
		s.k.Log.Error("auth admin: "+op+" failed", "err", err)
	}
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func (s *Service) mountAdminRoutes(rl *rateLimiter) {
	if s.driver() != "base" {
		return
	}
	r := s.k.Router
	// A generous cap for a human administrator, a hard stop for a runaway
	// script, on the routes that mint credentials.
	sensitive := newRateLimiter(60, 5*time.Minute).limit
	// The magic-link consume endpoint is public by design (the link is the
	// credential), so it shares the login rate limit.
	r.Get("/api/auth/magic", rl.limit(s.handleMagicConsume))
	// Ending an impersonation needs only the impersonation token itself.
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/impersonation/stop", s.handleImpersonationStop)

	r.Route("/api/auth/admin", func(ar chi.Router) {
		ar.Use(s.requireAdmin)
		ar.Get("/users", s.adminListUsers)
		ar.Get("/users/{id}", s.adminGetUser)
		ar.With(s.csrfGuard).Post("/users", s.adminCreateUser)
		ar.With(s.csrfGuard).Patch("/users/{id}", s.adminUpdateUser)
		ar.With(s.csrfGuard).Delete("/users/{id}", s.adminDeleteUser)
		ar.With(s.csrfGuard).Post("/users/{id}/impersonate", sensitive(s.adminImpersonate))
		ar.With(s.csrfGuard).Post("/users/{id}/reset-password", sensitive(s.adminResetPassword))
		ar.With(s.csrfGuard).Post("/users/{id}/magic-link", sensitive(s.adminMagicLink))
	})
}

// requireAdmin authenticates the request and verifies, against the current
// user record, that the caller is an administrator.
func (s *Service) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.authenticate(r)
		if err != nil || id == nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		ctx := r.Context()
		u, err := s.userByID(ctx, id.ID)
		if err != nil {
			s.adminInternal(w, "load caller", err)
			return
		}
		if u == nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized") // deleted account
			return
		}
		// An API token is scoped by its abilities and an impersonated session is
		// borrowed: neither may act with the owner's administrator role.
		if id.Guard == "pat" || id.Impersonator != "" || !isAdminUser(u) {
			s.deny(r, id)
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxKey{}, u.identity(s.def))))
	})
}

// deny records an access-control denial (never the credentials).
func (s *Service) deny(r *http.Request, id *Identity) {
	if s.k != nil && s.k.Log != nil {
		s.k.Log.Warn("auth admin: access denied", "user_id", id.ID, "guard", id.Guard,
			"impersonated", id.Impersonator != "", "method", r.Method, "path", r.URL.Path)
	}
}

// noImpersonation refuses a session that is borrowing another account, on the
// routes that change how that account authenticates.
func (s *Service) noImpersonation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := IdentityFrom(r.Context()); ok && id.Impersonator != "" {
			writeErr(w, http.StatusForbidden, "not available while impersonating")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- queries ---------------------------------------------------------------

func (s *Service) userByID(ctx context.Context, id string) (*User, error) {
	if id == "" {
		return nil, nil
	}
	return s.users().Find(ctx, id)
}

// escapeLike makes user input literal inside a LIKE pattern (ESCAPE '\').
func escapeLike(q string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(q)
}

func (s *Service) adminListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	limit := clampInt(r.URL.Query().Get("limit"), defaultListLimit, 1, maxListLimit)
	offset := clampInt(r.URL.Query().Get("offset"), 0, 0, 1<<31-1)
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	if len(q) > 254 {
		q = q[:254]
	}

	db, err := s.k.SQL(ctx)
	if err != nil {
		s.adminInternal(w, "list users", err)
		return
	}
	query := "SELECT id, email, roles, permissions, created_at FROM users"
	args := []any{}
	n := 0
	if q != "" {
		n++
		query += " WHERE LOWER(email) LIKE " + s.ph(n) + ` ESCAPE '\'`
		args = append(args, "%"+escapeLike(q)+"%")
	}
	query += " ORDER BY created_at DESC, id"
	n++
	query += " LIMIT " + s.ph(n)
	args = append(args, limit)
	n++
	query += " OFFSET " + s.ph(n) //#nosec G202 -- only dialect placeholders are concatenated; values are parameterized
	args = append(args, offset)

	rows, err := db.QueryContext(ctx, query, args...) //#nosec G202 -- only dialect placeholders are concatenated; values are parameterized
	if err != nil {
		s.adminInternal(w, "list users", err)
		return
	}
	defer func() { _ = rows.Close() }()
	out := []adminUser{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Email, &u.Roles, &u.Permissions, &u.CreatedAt); err != nil {
			s.adminInternal(w, "scan user", err)
			return
		}
		out = append(out, toAdminUser(&u))
	}
	if err := rows.Err(); err != nil {
		s.adminInternal(w, "list users", err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func clampInt(raw string, def, lo, hi int) int {
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// countAdmins returns how many accounts hold exactly the admin role.
func (s *Service) countAdmins(ctx context.Context) (int, error) {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return 0, err
	}
	rows, err := db.QueryContext(ctx, `SELECT roles FROM users WHERE roles LIKE '%admin%'`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var roles string
		if err := rows.Scan(&roles); err != nil {
			return 0, err
		}
		if contains(splitCSV(roles), adminRole) {
			n++
		}
	}
	return n, rows.Err()
}

// ---- input -----------------------------------------------------------------

// decodeBody reads a bounded JSON body. An empty body leaves v untouched. A
// malformed one is answered with a generic 400 (never the decoder's message).
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// cleanList validates roles or permissions: they are stored comma-joined, so a
// comma inside one would forge another.
func cleanList(in []string) ([]string, bool) {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if len(v) > maxListEntryLen || strings.Contains(v, ",") {
			return nil, false
		}
		for _, r := range v {
			if unicode.IsControl(r) {
				return nil, false
			}
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out, len(out) <= maxListEntries
}

func actorOf(r *http.Request) string {
	if id, ok := IdentityFrom(r.Context()); ok {
		return id.ID
	}
	return ""
}

// ---- handlers --------------------------------------------------------------

func (s *Service) adminGetUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.userByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "get user", err)
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toAdminUser(u))
}

func (s *Service) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string   `json:"email"`
		Password    string   `json:"password"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	email := normalizeEmail(body.Email)
	if email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	if !validEmail(email) {
		writeErr(w, http.StatusUnprocessableEntity, errInvalidEmail.Error())
		return
	}
	roles, ok := cleanList(body.Roles)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "invalid roles")
		return
	}
	perms, ok := cleanList(body.Permissions)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "invalid permissions")
		return
	}
	// No password makes a passwordless account: the stored value is not a bcrypt
	// hash, so no password can ever match it. The admin hands the user a link.
	hash := "!no-password"
	if body.Password != "" {
		if err := validatePassword(body.Password); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		h, err := hashPassword(body.Password)
		if err != nil {
			s.adminInternal(w, "hash password", err)
			return
		}
		hash = h
	}

	ctx := r.Context()
	s.adminMu.Lock()
	defer s.adminMu.Unlock()
	if existing, err := s.userByEmail(ctx, email); err != nil {
		s.adminInternal(w, "check email", err)
		return
	} else if existing != nil {
		writeErr(w, http.StatusConflict, "a user with that email already exists")
		return
	}
	u := User{ID: genID(), Email: email, PasswordHash: hash, Roles: strings.Join(roles, ","),
		Permissions: strings.Join(perms, ","), CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := s.users().Create(ctx, map[string]any{
		"id": u.ID, "email": u.Email, "password_hash": u.PasswordHash,
		"roles": u.Roles, "permissions": u.Permissions, "created_at": u.CreatedAt,
	}); err != nil {
		// Lost a race with another writer for the same address.
		if existing, qerr := s.userByEmail(ctx, email); qerr == nil && existing != nil {
			writeErr(w, http.StatusConflict, "a user with that email already exists")
			return
		}
		s.adminInternal(w, "create user", err)
		return
	}
	s.fire(ctx, EventUserCreated, map[string]string{"actor_id": actorOf(r), "user_id": u.ID, "email": u.Email})
	writeJSON(w, http.StatusCreated, map[string]any{"user": toAdminUser(&u)})
}

func (s *Service) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       *string   `json:"email"`
		Roles       *[]string `json:"roles"`
		Permissions *[]string `json:"permissions"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Email == nil && body.Roles == nil && body.Permissions == nil {
		writeErr(w, http.StatusBadRequest, "nothing to update")
		return
	}
	ctx := r.Context()
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	u, err := s.userByID(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "load user", err)
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}

	sets, args, fields := []string{}, []any{}, []string{}
	add := func(col string, v any) {
		args = append(args, v)
		sets = append(sets, col+" = "+s.ph(len(args)))
		fields = append(fields, col)
	}
	if body.Email != nil {
		email := normalizeEmail(*body.Email)
		if !validEmail(email) {
			writeErr(w, http.StatusUnprocessableEntity, errInvalidEmail.Error())
			return
		}
		if email != u.Email {
			other, err := s.userByEmail(ctx, email)
			if err != nil {
				s.adminInternal(w, "check email", err)
				return
			}
			if other != nil && other.ID != u.ID {
				writeErr(w, http.StatusConflict, "a user with that email already exists")
				return
			}
			add("email", email)
		}
	}
	if body.Roles != nil {
		roles, ok := cleanList(*body.Roles)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "invalid roles")
			return
		}
		if isAdminUser(u) && !contains(roles, adminRole) {
			if !s.otherAdminExists(w, ctx) {
				return
			}
		}
		add("roles", strings.Join(roles, ","))
	}
	if body.Permissions != nil {
		perms, ok := cleanList(*body.Permissions)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "invalid permissions")
			return
		}
		add("permissions", strings.Join(perms, ","))
	}

	if len(sets) > 0 {
		db, err := s.k.SQL(ctx)
		if err != nil {
			s.adminInternal(w, "update user", err)
			return
		}
		args = append(args, u.ID)
		q := "UPDATE users SET " + strings.Join(sets, ", ") + " WHERE id = " + s.ph(len(args)) //#nosec G202 -- column names are constants; values parameterized
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			if body.Email != nil {
				if other, qerr := s.userByEmail(ctx, normalizeEmail(*body.Email)); qerr == nil && other != nil && other.ID != u.ID {
					writeErr(w, http.StatusConflict, "a user with that email already exists")
					return
				}
			}
			s.adminInternal(w, "update user", err)
			return
		}
		s.fire(ctx, EventUserUpdated, map[string]string{"actor_id": actorOf(r), "user_id": u.ID, "fields": strings.Join(fields, ",")})
	}
	updated, err := s.userByID(ctx, u.ID)
	if err != nil || updated == nil {
		s.adminInternal(w, "reload user", err)
		return
	}
	writeJSON(w, http.StatusOK, toAdminUser(updated))
}

// otherAdminExists reports whether removing one admin leaves another. On false
// it has already answered the request (409, or 500 on a database error).
func (s *Service) otherAdminExists(w http.ResponseWriter, ctx context.Context) bool {
	n, err := s.countAdmins(ctx)
	if err != nil {
		s.adminInternal(w, "count admins", err)
		return false
	}
	if n <= 1 {
		writeErr(w, http.StatusConflict, "cannot remove the last administrator")
		return false
	}
	return true
}

func (s *Service) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.adminMu.Lock()
	defer s.adminMu.Unlock()

	u, err := s.userByID(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "load user", err)
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if isAdminUser(u) && !s.otherAdminExists(w, ctx) {
		return
	}
	db, err := s.k.SQL(ctx)
	if err != nil {
		s.adminInternal(w, "delete user", err)
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		s.adminInternal(w, "delete user", err)
		return
	}
	defer func() { _ = tx.Rollback() }()
	// The user's credentials and tokens go with the account.
	for _, q := range []struct{ sql, arg string }{
		{"DELETE FROM personal_access_tokens WHERE user_id = ", u.ID},
		{"DELETE FROM auth_password_resets WHERE user_id = ", u.ID},
		{"DELETE FROM auth_magic_links WHERE user_id = ", u.ID},
		{"DELETE FROM auth_totp WHERE subject = ", u.ID},
		{"DELETE FROM auth_pins WHERE subject = ", u.ID},
		{"DELETE FROM otp_codes WHERE subject = ", u.Email},
		{"DELETE FROM users WHERE id = ", u.ID},
	} {
		if _, err := tx.ExecContext(ctx, q.sql+s.ph(1), q.arg); err != nil { //#nosec G202 -- constant statements; dialect placeholder; value parameterized
			s.adminInternal(w, "delete user", err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		s.adminInternal(w, "delete user", err)
		return
	}
	s.fire(ctx, EventUserDeleted, map[string]string{"actor_id": actorOf(r), "user_id": u.ID, "email": u.Email})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": u.ID})
}

func (s *Service) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	u, err := s.userByID(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "load user", err)
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if body.Password != "" {
		switch err := s.setPasswordBy(ctx, u.ID, body.Password, actorOf(r)); {
		case err == nil:
			writeJSON(w, http.StatusOK, map[string]any{"reset": true})
		case errors.Is(err, errPolicy), errors.Is(err, errTooLong):
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
		case errors.Is(err, ErrUserNotFound):
			writeErr(w, http.StatusNotFound, "user not found")
		default:
			s.adminInternal(w, "set password", err)
		}
		return
	}
	// No password: hand the administrator a single-use reset link.
	token, exp, err := s.createAdminResetToken(ctx, u.ID)
	if err != nil {
		s.adminInternal(w, "create reset link", err)
		return
	}
	expires := exp.Format(time.RFC3339)
	s.fire(ctx, EventAdminResetLinkIssued, map[string]string{"actor_id": actorOf(r), "user_id": u.ID, "expires_at": expires})
	writeJSON(w, http.StatusOK, map[string]any{"link": resetLink(token), "emailed": false, "expires_at": expires})
}

func (s *Service) adminMagicLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, err := s.userByID(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "load user", err)
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	token, exp, err := s.createMagicToken(ctx, u.ID, actorOf(r))
	if err != nil {
		s.adminInternal(w, "create magic link", err)
		return
	}
	expires := exp.Format(time.RFC3339)
	s.fire(ctx, EventMagicLinkIssued, map[string]string{"actor_id": actorOf(r), "user_id": u.ID, "expires_at": expires})
	writeJSON(w, http.StatusOK, map[string]any{"link": magicLink(token), "emailed": false, "expires_at": expires})
}
