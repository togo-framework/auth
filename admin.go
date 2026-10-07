package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
)

// Admin user management: /api/auth/admin/*.
//
// Authenticated does not mean administrator. Every route here goes through
// requireAdmin, which authenticates the caller (authenticate revalidates the
// account against the database on every request) and requires the admin role
// from that current record, so a token minted before a demotion or deletion
// stops working at once. Each mutation re-checks the caller inside its own
// transaction too (adminTx), so a demotion that commits while a request is in
// flight is honoured at the write. A caller with no valid credentials gets 401; a signed-in
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
		// authenticate has already replaced the token's roles with the account's
		// current ones and refused a deleted account (revalidate), so HasRole is
		// the database's answer, not a claim.
		//
		// An API token is scoped by its abilities and an impersonated session is
		// borrowed: neither may act with the owner's administrator role.
		if id.Guard == "pat" || id.Impersonator != "" || !id.HasRole(adminRole) {
			s.deny(r, id)
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		caller := *id
		caller.Guard = s.def
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &caller)))
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
	if !plausibleID(id) {
		return nil, nil
	}
	return s.users().Find(ctx, id)
}

// plausibleID rejects ids no account can have (empty, oversized, NUL or
// invalid UTF-8, which PostgreSQL refuses outright) before they reach SQL.
func plausibleID(id string) bool {
	return id != "" && len(id) <= 128 && utf8.ValidString(id) && !strings.ContainsRune(id, 0)
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
	// NUL and invalid UTF-8 make PostgreSQL error out; neither can be part of an
	// email, so drop them rather than fail the search.
	q := strings.ToValidUTF8(strings.ReplaceAll(r.URL.Query().Get("q"), "\x00", ""), "")
	q = strings.ToLower(strings.TrimSpace(q))
	if len(q) > 254 {
		q = strings.ToValidUTF8(q[:254], "")
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
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
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

// httpError is a failure with a client-safe status and message.
type httpError struct {
	status int
	msg    string
	body   any // optional JSON body that replaces {"error": msg}
}

func (e *httpError) Error() string { return e.msg }

func conflict(msg string) error { return &httpError{status: http.StatusConflict, msg: msg} }

// failAdmin answers err: a client-safe httpError as is, anything else as a
// logged, generic 500.
func (s *Service) failAdmin(w http.ResponseWriter, op string, err error) {
	var he *httpError
	if errors.As(err, &he) {
		if he.body != nil {
			writeJSON(w, he.status, he.body)
			return
		}
		writeErr(w, he.status, he.msg)
		return
	}
	s.adminInternal(w, op, err)
}

// adminTx runs fn in a transaction that first takes a row lock on a single
// sentinel row, so admin mutations serialise across processes and instances
// (an in-process mutex cannot do that). Whatever fn reads after the lock is
// the committed state left by the previous holder, which is what makes the
// last-admin and email-uniqueness checks race-free.
func (s *Service) adminTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, "UPDATE auth_admin_guard SET n = n + 1 WHERE id = 1"); err != nil {
		return err
	}
	// The caller was judged an administrator before the transaction began; judge
	// again now that the guard is held, so a demotion or deletion that committed
	// in between stops the write.
	if actor, ok := IdentityFrom(ctx); ok {
		if err := s.txRequireAdmin(ctx, tx, actor.ID); err != nil {
			return err
		}
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// txUser reads one account inside tx (nil when absent).
func (s *Service) txUser(ctx context.Context, tx *sql.Tx, id string) (*User, error) {
	if !plausibleID(id) {
		return nil, nil
	}
	var u User
	//#nosec G202 -- dialect placeholder only; value parameterized
	err := tx.QueryRowContext(ctx, "SELECT id, email, roles, permissions, created_at FROM users WHERE id = "+s.ph(1), id).
		Scan(&u.ID, &u.Email, &u.Roles, &u.Permissions, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// txRequireAdmin fails unless actorID is, inside tx, an existing administrator.
func (s *Service) txRequireAdmin(ctx context.Context, tx *sql.Tx, actorID string) error {
	a, err := s.txUser(ctx, tx, actorID)
	if err != nil {
		return err
	}
	if a == nil {
		return &httpError{status: http.StatusUnauthorized, msg: "unauthorized"}
	}
	if !isAdminUser(a) {
		return &httpError{status: http.StatusForbidden, msg: "forbidden"}
	}
	return nil
}

// txLockUser takes the row lock on one account with a no-op UPDATE (portable:
// SQLite has no FOR UPDATE, and it serialises writers anyway). It reports
// whether the account exists. Everything read after it in the same transaction
// is the state left by the previous writer, and writers that come later wait.
func (s *Service) txLockUser(ctx context.Context, tx *sql.Tx, id string) (bool, error) {
	if !plausibleID(id) {
		return false, nil
	}
	//#nosec G202 -- dialect placeholder only; value parameterized
	res, err := tx.ExecContext(ctx, "UPDATE users SET roles = roles WHERE id = "+s.ph(1), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// txSetPasswordIfRoles is the effect statement of every credential write that an
// administrator influenced: the password changes only if the account's roles
// are still exactly the value that was read and judged non-administrator, in
// the same statement. It reports whether a row changed; false means the account
// changed under the operation (promoted, demoted, edited or deleted) and the
// caller must refuse. Roles equality, not a LIKE test, because it is
// dialect-neutral and exact.
func (s *Service) txSetPasswordIfRoles(ctx context.Context, tx *sql.Tx, userID, hash, roles string) (bool, error) {
	//#nosec G202 -- dialect placeholders only; values parameterized
	res, err := tx.ExecContext(ctx, "UPDATE users SET password_hash = "+s.ph(1)+" WHERE id = "+s.ph(2)+" AND roles = "+s.ph(3), hash, userID, roles)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// emailTaken reports whether another account (not exceptID) already uses email
// in any letter case, so legacy mixed-case rows count.
func (s *Service) emailTaken(ctx context.Context, tx *sql.Tx, email, exceptID string) (bool, error) {
	var id string
	//#nosec G202 -- dialect placeholders only; values parameterized
	err := tx.QueryRowContext(ctx, "SELECT id FROM users WHERE LOWER(email) = "+s.ph(1)+" AND id <> "+s.ph(2)+" LIMIT 1", normalizeEmail(email), exceptID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// otherAdmins counts the administrators other than exceptID, inside tx.
func (s *Service) otherAdmins(ctx context.Context, tx *sql.Tx, exceptID string) (int, error) {
	//#nosec G202 -- dialect placeholder only; value parameterized
	rows, err := tx.QueryContext(ctx, `SELECT roles FROM users WHERE roles LIKE '%admin%' AND id <> `+s.ph(1), exceptID)
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

var errLastAdmin = conflict("cannot remove the last administrator")

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
	u := User{ID: genID(), Email: email, PasswordHash: hash, Roles: strings.Join(roles, ","),
		Permissions: strings.Join(perms, ","), CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	err := s.adminTx(ctx, func(tx *sql.Tx) error {
		if taken, err := s.emailTaken(ctx, tx, email, ""); err != nil {
			return err
		} else if taken {
			return conflict("a user with that email already exists")
		}
		//#nosec G202 -- dialect placeholders only; values parameterized
		if _, err := tx.ExecContext(ctx, "INSERT INTO users (id, email, password_hash, roles, permissions, created_at) VALUES ("+
			s.ph(1)+", "+s.ph(2)+", "+s.ph(3)+", "+s.ph(4)+", "+s.ph(5)+", "+s.ph(6)+")",
			u.ID, u.Email, u.PasswordHash, u.Roles, u.Permissions, u.CreatedAt); err != nil {
			return err
		}
		// The creator chose the email and, if given, knows the password: record
		// both so a different administrator promoting this account must accept.
		if err := s.markProvenance(ctx, tx, u.ID, fieldEmail, actorOf(r)); err != nil {
			return err
		}
		if body.Password != "" {
			return s.markProvenance(ctx, tx, u.ID, fieldPassword, actorOf(r))
		}
		return nil
	})
	if err != nil {
		s.failAdmin(w, "create user", err)
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
		// Accept confirms, for this one request, a promotion of an account whose
		// email or password another administrator set (see admin_state.go).
		Accept bool `json:"accept_identity_set_by_other"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	if body.Email == nil && body.Roles == nil && body.Permissions == nil {
		writeErr(w, http.StatusBadRequest, "nothing to update")
		return
	}
	// Validate input before touching the database.
	var email string
	if body.Email != nil {
		if email = normalizeEmail(*body.Email); !validEmail(email) {
			writeErr(w, http.StatusUnprocessableEntity, errInvalidEmail.Error())
			return
		}
	}
	var roles, perms []string
	var ok bool
	if body.Roles != nil {
		if roles, ok = cleanList(*body.Roles); !ok {
			writeErr(w, http.StatusUnprocessableEntity, "invalid roles")
			return
		}
	}
	if body.Permissions != nil {
		if perms, ok = cleanList(*body.Permissions); !ok {
			writeErr(w, http.StatusUnprocessableEntity, "invalid permissions")
			return
		}
	}

	ctx := r.Context()
	id := chi.URLParam(r, "id")
	var updated, before *User
	crossOp := ""
	fields := []string{}
	var promoted, demoted, accepted bool
	var tainted []string
	err := s.adminTx(ctx, func(tx *sql.Tx) error {
		// The target row lock is the first statement on the target: a redemption
		// or password write holding it commits its provenance before it is read
		// below, and a later one is refused by its own roles check.
		found, err := s.txLockUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if !found {
			return &httpError{status: http.StatusNotFound, msg: "user not found"}
		}
		u, err := s.txUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if u == nil {
			return &httpError{status: http.StatusNotFound, msg: "user not found"}
		}
		actorID := actorOf(r)
		emailChanges := body.Email != nil && email != u.Email
		promoted = body.Roles != nil && contains(roles, adminRole) && !isAdminUser(u)
		demoted = body.Roles != nil && !contains(roles, adminRole) && isAdminUser(u)
		if promoted {
			// Provenance is read after the lock and before any write. An email this
			// same request sets is the promoter's own, so it is exempt.
			prov, err := s.readProvenance(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			tainted = prov.taintedFields(u.ID, actorID, emailChanges)
			if len(tainted) > 0 {
				if !body.Accept {
					return provenanceConflict(prov, tainted)
				}
				accepted = true
				if err := s.recordAccept(ctx, tx, u.ID, actorID); err != nil {
					return err
				}
			}
		}
		// Another administrator's identity and privileges are off limits by
		// default: a role change plus an email change plus a reset (or a
		// demotion and re-promotion) would otherwise be a takeover. Self-edits,
		// promoting a non-admin and deleting stay allowed (and audited).
		if (body.Roles != nil || body.Permissions != nil || (body.Email != nil && email != u.Email)) && isAdminUser(u) {
			if err := s.adminTargetErr(r, u); err != nil {
				return err
			}
			before = u
			crossOp = "update"
		}
		sets, args := []string{}, []any{}
		add := func(col string, v any) {
			args = append(args, v)
			sets = append(sets, col+" = "+s.ph(len(args)))
			fields = append(fields, col)
		}
		if body.Email != nil && email != u.Email {
			// Changing another administrator's email hands over the account via
			// the public password-reset flow, so it follows the same rule as
			// reset-password and magic-link. Roles, permissions and delete of
			// other administrators stay allowed (and audited).
			if err := s.adminTargetErr(r, u); err != nil {
				return err
			}
			if taken, err := s.emailTaken(ctx, tx, email, u.ID); err != nil {
				return err
			} else if taken {
				return conflict("a user with that email already exists")
			}
			add("email", email)
			if err := s.markProvenance(ctx, tx, u.ID, fieldEmail, actorID); err != nil {
				return err
			}
		}
		if body.Roles != nil {
			if isAdminUser(u) && !contains(roles, adminRole) {
				if n, err := s.otherAdmins(ctx, tx, u.ID); err != nil {
					return err
				} else if n == 0 {
					return errLastAdmin
				}
			}
			add("roles", strings.Join(roles, ","))
		}
		if body.Permissions != nil {
			add("permissions", strings.Join(perms, ","))
		}
		if len(sets) > 0 {
			args = append(args, u.ID)
			//#nosec G202 -- column names are constants; values parameterized
			if _, err := tx.ExecContext(ctx, "UPDATE users SET "+strings.Join(sets, ", ")+" WHERE id = "+s.ph(len(args)), args...); err != nil {
				return err
			}
		}
		updated, err = s.txUser(ctx, tx, u.ID)
		return err
	})
	if err != nil {
		s.failAdmin(w, "update user", err)
		return
	}
	if crossOp != "" && len(fields) > 0 {
		s.auditCross(ctx, actorOf(r), before, "update:"+strings.Join(fields, ","))
	}
	if len(fields) > 0 {
		s.fire(ctx, EventUserUpdated, map[string]string{"actor_id": actorOf(r), "target_id": updated.ID, "user_id": updated.ID, "fields": strings.Join(fields, ",")})
	}
	if promoted {
		s.fire(ctx, EventAdminPromoted, map[string]string{"actor_id": actorOf(r), "target_id": updated.ID, "tainted": strings.Join(tainted, ","), "accepted": strconv.FormatBool(accepted)})
	}
	if demoted {
		s.fire(ctx, EventAdminDemoted, map[string]string{"actor_id": actorOf(r), "target_id": updated.ID})
	}
	writeJSON(w, http.StatusOK, toAdminUser(updated))
}

func (s *Service) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var gone *User
	err := s.adminTx(ctx, func(tx *sql.Tx) error {
		u, err := s.txUser(ctx, tx, chi.URLParam(r, "id"))
		if err != nil {
			return err
		}
		if u == nil {
			return &httpError{status: http.StatusNotFound, msg: "user not found"}
		}
		if isAdminUser(u) {
			if n, err := s.otherAdmins(ctx, tx, u.ID); err != nil {
				return err
			} else if n == 0 {
				return errLastAdmin
			}
		}
		// The user's credentials and tokens go with the account.
		for _, q := range []struct{ sql, arg string }{
			{"DELETE FROM personal_access_tokens WHERE user_id = ", u.ID},
			{"DELETE FROM auth_password_resets WHERE user_id = ", u.ID},
			{"DELETE FROM auth_magic_links WHERE user_id = ", u.ID},
			{"DELETE FROM auth_totp WHERE subject = ", u.ID},
			{"DELETE FROM auth_pins WHERE subject = ", u.ID},
			{"DELETE FROM auth_account_state WHERE user_id = ", u.ID},
			{"DELETE FROM otp_codes WHERE subject = ", u.Email},
			{"DELETE FROM users WHERE id = ", u.ID},
		} {
			if _, err := tx.ExecContext(ctx, q.sql+s.ph(1), q.arg); err != nil { //#nosec G202 -- constant statements; dialect placeholder; value parameterized
				return err
			}
		}
		gone = u
		return nil
	})
	if err != nil {
		s.failAdmin(w, "delete user", err)
		return
	}
	if isAdminUser(gone) {
		s.auditCross(ctx, actorOf(r), gone, "delete")
	}
	s.fire(ctx, EventUserDeleted, map[string]string{"actor_id": actorOf(r), "target_id": gone.ID, "user_id": gone.ID, "email": gone.Email})
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": gone.ID})
}

// refuseAdminTarget answers 403 and returns true when target is an
// administrator other than the caller and AUTH_ADMIN_CROSS_CONTROL is not set.
// Impersonating, setting the password of, or minting a sign-in link for another
// administrator are all ways of becoming them, so one rule covers all three.
func (s *Service) refuseAdminTarget(w http.ResponseWriter, r *http.Request, target *User) bool {
	if err := s.adminTargetErr(r, target); err != nil {
		s.failAdmin(w, "admin target", err)
		return true
	}
	return false
}

// auditCross records an operation performed on another administrator under the
// AUTH_ADMIN_CROSS_CONTROL exception (a no-op for ordinary targets and
// self-edits), naming actor, target, the operation and the policy used.
func (s *Service) auditCross(ctx context.Context, actorID string, target *User, op string) {
	if target == nil || target.ID == actorID || !isAdminUser(target) || !crossControlAllowed() {
		return
	}
	s.fire(ctx, EventAdminCrossControl, map[string]string{
		"actor_id": actorID, "target_id": target.ID, "operation": op, "policy": "AUTH_ADMIN_CROSS_CONTROL",
	})
}

// adminTargetErr is refuseAdminTarget as an error, for use inside a transaction.
func (s *Service) adminTargetErr(r *http.Request, target *User) error {
	actor, _ := IdentityFrom(r.Context())
	if actor == nil || target.ID == actor.ID || !isAdminUser(target) || crossControlAllowed() {
		return nil
	}
	s.deny(r, actor)
	return &httpError{status: http.StatusForbidden, msg: "administrators cannot be acted on this way"}
}

func (s *Service) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if !decodeBody(w, r, &body) {
		return
	}
	ctx := r.Context()
	if body.Password != "" {
		u, err := s.adminSetPassword(ctx, r, chi.URLParam(r, "id"), body.Password)
		switch {
		case err == nil:
			s.auditCross(ctx, actorOf(r), u, "set-password")
			s.fire(ctx, EventPasswordChanged, map[string]string{"user_id": u.ID, "by": "admin", "actor_id": actorOf(r)})
			writeJSON(w, http.StatusOK, map[string]any{"reset": true})
		case errors.Is(err, errPolicy), errors.Is(err, errTooLong):
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
		default:
			s.failAdmin(w, "set password", err)
		}
		return
	}
	u, err := s.userByID(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "load user", err)
		return
	}
	if u == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if s.refuseAdminTarget(w, r, u) {
		return
	}
	// No password: hand the administrator a single-use reset link.
	token, exp, err := s.createAdminResetToken(ctx, u.ID, actorOf(r))
	if err != nil {
		s.adminInternal(w, "create reset link", err)
		return
	}
	expires := exp.Format(time.RFC3339)
	s.auditCross(ctx, actorOf(r), u, "reset-link")
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
	if s.refuseAdminTarget(w, r, u) {
		return
	}
	token, exp, err := s.createMagicToken(ctx, u.ID, actorOf(r))
	if err != nil {
		s.adminInternal(w, "create magic link", err)
		return
	}
	expires := exp.Format(time.RFC3339)
	s.auditCross(ctx, actorOf(r), u, "magic-link")
	s.fire(ctx, EventMagicLinkIssued, map[string]string{"actor_id": actorOf(r), "user_id": u.ID, "expires_at": expires})
	writeJSON(w, http.StatusOK, map[string]any{"link": magicLink(token), "emailed": false, "expires_at": expires})
}

// adminSetPassword is the admin set-password mode: one transaction that locks
// the target, judges it, and writes the hash only while the roles value it
// judged is still the stored one. A zero-row write means the account changed
// (promoted) after the judgement, so nothing is written and the refusal is
// reported as a 409 and an auth.credential_refused event. The provenance of
// the password is the acting administrator.
func (s *Service) adminSetPassword(ctx context.Context, r *http.Request, id, password string) (*User, error) {
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := hashPassword(password) // before the transaction: bcrypt must not hold the guard
	if err != nil {
		return nil, err
	}
	actorID := actorOf(r)
	var target *User
	refused := false
	err = s.adminTx(ctx, func(tx *sql.Tx) error {
		found, err := s.txLockUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if !found {
			return &httpError{status: http.StatusNotFound, msg: "user not found"}
		}
		u, err := s.txUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if u == nil {
			return &httpError{status: http.StatusNotFound, msg: "user not found"}
		}
		if err := s.adminTargetErr(r, u); err != nil {
			return err
		}
		ok, err := s.txSetPasswordIfRoles(ctx, tx, u.ID, hash, u.Roles)
		if err != nil {
			return err
		}
		if !ok {
			refused = true
			return nil
		}
		target = u
		return s.markProvenance(ctx, tx, u.ID, fieldPassword, actorID)
	})
	if err != nil {
		return nil, err
	}
	if refused {
		s.fire(ctx, EventCredentialRefused, map[string]string{"type": "set-password", "issuer": actorID, "target_id": id})
		return nil, conflict("the account changed while the password was being set; retry")
	}
	return target, nil
}
