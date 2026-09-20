package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Admin user-management surface. Every togo app that mounts auth gets a guarded
// CRUD + impersonation + reset/magic-link API out of the box, backed by the same
// `users` table, password hashing (bcrypt) and IssueToken the login flow uses.
//
// Routes mount under /api/auth/admin/* behind RequireRole("admin"); writes also
// carry the double-submit CSRF guard (bearer requests are exempt, like the rest
// of the plugin). The signed magic/reset links consume at the public
// /api/auth/magic endpoint and are HMAC'd with the plugin's existing AUTH_SECRET
// — no new secret, no SMTP dependency: when no mailer is wired the link is
// returned in the response (emailed:false) and an event is fired so a mail
// plugin can deliver it.

// adminUser is the admin-facing shape of an account: roles/permissions are parsed
// from the comma-encoded TEXT columns into arrays.
type adminUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
}

func listOf(s string) []string {
	if v := splitCSV(s); v != nil {
		return v
	}
	return []string{}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// mountAdminRoutes wires the admin user-management API + the public magic-link
// consume endpoint. Called from mountRoutes.
func (s *Service) mountAdminRoutes(r chi.Router) {
	r.Route("/api/auth/admin", func(ar chi.Router) {
		ar.Use(s.RequireRole("admin"))
		ar.Get("/users", s.adminListUsersHandler)
		ar.Get("/users/{id}", s.adminGetUserHandler)
		ar.With(s.csrfGuard).Post("/users", s.adminCreateUser)
		ar.With(s.csrfGuard).Patch("/users/{id}", s.adminUpdateUser)
		ar.With(s.csrfGuard).Delete("/users/{id}", s.adminDeleteUser)
		ar.With(s.csrfGuard).Post("/users/{id}/impersonate", s.adminImpersonate)
		ar.With(s.csrfGuard).Post("/users/{id}/reset-password", s.adminResetPassword)
		ar.With(s.csrfGuard).Post("/users/{id}/magic-link", s.adminMagicLink)
	})
	// Public auto-login target for magic + admin-issued reset links.
	r.Get("/api/auth/magic", s.handleMagicConsume)
}

// ---- lookups ----

// adminListUsers reads the users table directly (so created_at ordering and the
// raw roles/permissions columns are available for the admin surface).
func (s *Service) adminListUsers(ctx context.Context, q string) []adminUser {
	db, err := s.k.SQL(ctx)
	if err != nil || db == nil {
		return []adminUser{}
	}
	rows, err := db.QueryContext(ctx, `SELECT id, email, COALESCE(roles,''), COALESCE(permissions,''), created_at FROM users ORDER BY created_at DESC LIMIT 500`)
	if err != nil {
		return []adminUser{}
	}
	defer rows.Close()
	out := []adminUser{}
	ql := strings.ToLower(strings.TrimSpace(q))
	for rows.Next() {
		var u adminUser
		var roles, perms, created string
		if err := rows.Scan(&u.ID, &u.Email, &roles, &perms, &created); err != nil {
			continue
		}
		u.Roles = listOf(roles)
		u.Permissions = listOf(perms)
		u.CreatedAt = created
		if ql != "" && !strings.Contains(strings.ToLower(u.Email), ql) {
			continue
		}
		out = append(out, u)
	}
	return out
}

// adminFindUser resolves a user by id or email.
func (s *Service) adminFindUser(ctx context.Context, idOrEmail string) (adminUser, bool) {
	for _, u := range s.adminListUsers(ctx, "") {
		if u.ID == idOrEmail || u.Email == idOrEmail {
			return u, true
		}
	}
	return adminUser{}, false
}

// ---- handlers ----

func (s *Service) adminListUsersHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.adminListUsers(r.Context(), r.URL.Query().Get("q")))
}

func (s *Service) adminGetUserHandler(w http.ResponseWriter, r *http.Request) {
	u, ok := s.adminFindUser(r.Context(), chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Service) adminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string   `json:"email"`
		Password    string   `json:"password"`
		Roles       []string `json:"roles"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}
	ctx := r.Context()
	if _, exists := s.adminFindUser(ctx, body.Email); exists {
		writeErr(w, http.StatusConflict, "a user with that email already exists")
		return
	}
	// Create the passwordless account via the auth service, then set roles/pw.
	if _, err := s.FindOrCreateByEmail(ctx, body.Email); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	db, err := s.k.SQL(ctx)
	if err != nil || db == nil {
		writeErr(w, http.StatusInternalServerError, "no database")
		return
	}
	p := s.ph
	_, _ = db.ExecContext(ctx, "UPDATE users SET roles="+p(1)+", permissions="+p(2)+" WHERE email="+p(3),
		strings.Join(body.Roles, ","), strings.Join(body.Permissions, ","), body.Email)
	note := ""
	if body.Password != "" {
		if h, herr := hashPassword(body.Password); herr == nil {
			_, _ = db.ExecContext(ctx, "UPDATE users SET password_hash="+p(1)+" WHERE email="+p(2), h, body.Email)
		}
	} else {
		note = "no password set — send a reset or magic link so the user can sign in"
	}
	u, _ := s.adminFindUser(ctx, body.Email)
	s.fire(ctx, EventUserCreated, u)
	writeJSON(w, http.StatusCreated, map[string]any{"user": u, "note": note})
}

func (s *Service) adminUpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, ok := s.adminFindUser(ctx, chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	var body struct {
		Email       *string   `json:"email"`
		Roles       *[]string `json:"roles"`
		Permissions *[]string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	db, err := s.k.SQL(ctx)
	if err != nil || db == nil {
		writeErr(w, http.StatusInternalServerError, "no database")
		return
	}
	p := s.ph
	if body.Email != nil && *body.Email != "" {
		_, _ = db.ExecContext(ctx, "UPDATE users SET email="+p(1)+" WHERE id="+p(2), strings.ToLower(*body.Email), u.ID)
	}
	if body.Roles != nil {
		_, _ = db.ExecContext(ctx, "UPDATE users SET roles="+p(1)+" WHERE id="+p(2), strings.Join(*body.Roles, ","), u.ID)
	}
	if body.Permissions != nil {
		_, _ = db.ExecContext(ctx, "UPDATE users SET permissions="+p(1)+" WHERE id="+p(2), strings.Join(*body.Permissions, ","), u.ID)
	}
	updated, _ := s.adminFindUser(ctx, u.ID)
	s.fire(ctx, EventUserUpdated, updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Service) adminDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, ok := s.adminFindUser(ctx, chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	// Never delete the last admin.
	admins := 0
	for _, x := range s.adminListUsers(ctx, "") {
		if contains(x.Roles, "admin") {
			admins++
		}
	}
	if contains(u.Roles, "admin") && admins <= 1 {
		writeErr(w, http.StatusConflict, "cannot delete the last admin")
		return
	}
	db, err := s.k.SQL(ctx)
	if err != nil || db == nil {
		writeErr(w, http.StatusInternalServerError, "no database")
		return
	}
	p := s.ph
	if _, err := db.ExecContext(ctx, "DELETE FROM users WHERE id="+p(1), u.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Best-effort cleanup of the user's personal access tokens.
	_, _ = db.ExecContext(ctx, "DELETE FROM personal_access_tokens WHERE user_id="+p(1), u.ID)
	s.fire(ctx, EventUserDeleted, u)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": u.ID})
}

func (s *Service) adminImpersonate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, ok := s.adminFindUser(ctx, chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	tok, err := s.IssueToken(Identity{ID: u.ID, Email: u.Email, Roles: u.Roles, Permissions: u.Permissions, Guard: s.def})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.fire(ctx, EventUserImpersonated, u)
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "identity": u})
}

func (s *Service) adminResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, ok := s.adminFindUser(ctx, chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Password != "" {
		if err := validatePassword(body.Password); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		db, err := s.k.SQL(ctx)
		if err != nil || db == nil {
			writeErr(w, http.StatusInternalServerError, "no database")
			return
		}
		h, herr := hashPassword(body.Password)
		if herr != nil {
			writeErr(w, http.StatusInternalServerError, herr.Error())
			return
		}
		if _, err := db.ExecContext(ctx, "UPDATE users SET password_hash="+s.ph(1)+" WHERE id="+s.ph(2), h, u.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.fire(ctx, EventPasswordChanged, u)
		writeJSON(w, http.StatusOK, map[string]any{"reset": true})
		return
	}
	// No password → return (or, if a mailer is wired, email) a magic login link.
	s.issueLinkResponse(w, r, u, EventPasswordReset)
}

func (s *Service) adminMagicLink(w http.ResponseWriter, r *http.Request) {
	u, ok := s.adminFindUser(r.Context(), chi.URLParam(r, "id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	s.issueLinkResponse(w, r, u, EventMagicLinkIssued)
}

// issueLinkResponse builds a signed magic link, fires an event (so a mail plugin
// can deliver it), and returns {link, emailed}. Mail is out of scope here, so
// emailed is always false unless a listener sets a future delivery flag.
func (s *Service) issueLinkResponse(w http.ResponseWriter, r *http.Request, u adminUser, event string) {
	link := s.magicLinkURL(r, u.ID)
	s.fire(r.Context(), event, map[string]any{"email": u.Email, "user_id": u.ID, "link": link})
	writeJSON(w, http.StatusOK, map[string]any{"link": link, "emailed": false})
}

// handleMagicConsume verifies a signed link, issues a session for the target
// user, and redirects to the post-login URL.
func (s *Service) handleMagicConsume(w http.ResponseWriter, r *http.Request) {
	uid, ok := s.verifyMagicToken(r.URL.Query().Get("token"))
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid or expired link")
		return
	}
	u, found := s.adminFindUser(r.Context(), uid)
	if !found {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if _, err := s.IssueSession(w, Identity{ID: u.ID, Email: u.Email, Roles: u.Roles, Permissions: u.Permissions, Guard: s.def}); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(w, r, postLoginURL(), http.StatusFound)
}

// ---- signed links (HMAC over the plugin's AUTH_SECRET) ----

const magicPurpose = "magic"

func (s *Service) signMagicToken(uid string, ttl time.Duration) string {
	payload := fmt.Sprintf("%s|%s|%d", uid, magicPurpose, time.Now().Add(ttl).Unix())
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func (s *Service) verifyMagicToken(tok string) (string, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, s.secret)
	mac.Write(payload)
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return "", false
	}
	f := strings.Split(string(payload), "|")
	if len(f) != 3 || f[1] != magicPurpose {
		return "", false
	}
	exp, _ := strconv.ParseInt(f[2], 10, 64)
	if time.Now().Unix() > exp {
		return "", false
	}
	return f[0], true
}

func (s *Service) magicLinkURL(r *http.Request, uid string) string {
	base := firstEnv("AUTH_PUBLIC_URL", "APP_URL", "PUBLIC_URL")
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	base = strings.TrimRight(base, "/")
	return base + "/api/auth/magic?token=" + s.signMagicToken(uid, time.Hour)
}

func postLoginURL() string {
	if v := firstEnv("AUTH_POST_LOGIN_URL", "DASHBOARD_URL", "APP_URL"); v != "" {
		return v
	}
	return "/"
}
