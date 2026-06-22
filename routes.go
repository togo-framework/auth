package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	errPolicy  = fmt.Errorf("password must be at least %d characters", minPasswordLen())
	errTooLong = errors.New("password must be at most 72 bytes")
)

// driver selects the auth backend: "base" (DB + JWT, default) or "supabase".
func (s *Service) driver() string {
	if d := os.Getenv("AUTH_DRIVER"); d != "" {
		return d
	}
	return "base"
}

// mountRoutes registers /api/auth/* on the kernel router with rate limiting +
// CSRF. Supabase/GoTrue is first-class (AUTH_DRIVER=supabase); other backends
// drop in as driver plugins.
func (s *Service) mountRoutes() {
	r := s.k.Router
	// Brute-force protection: 10 attempts / 5 min per IP on credential endpoints.
	rl := newRateLimiter(10, 5*time.Minute)

	r.With(s.csrfGuard).Post("/api/auth/register", rl.limit(s.handleRegister))
	r.With(s.csrfGuard).Post("/api/auth/login", rl.limit(s.handleLogin))
	r.Get("/api/auth/csrf", s.issueCSRF)
	r.Get("/api/auth/methods", s.handleMethods)
	r.With(s.Middleware).Get("/api/auth/me", s.handleMe)
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/change-password", s.handleChangePassword)
	r.With(s.Middleware).Post("/api/auth/logout", s.handleLogout)

	// MFA: OTP (delivery decoupled via EventOTPRequested), TOTP 2FA, PIN lock screen.
	r.With(s.csrfGuard).Post("/api/auth/otp", rl.limit(s.handleOTP))
	r.With(s.csrfGuard).Post("/api/auth/otp/verify", rl.limit(s.handleOTPVerify))
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/2fa/enroll", s.handle2FAEnroll)
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/2fa/verify", s.handle2FAVerify)
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/pin", s.handlePINSet)
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/pin/verify", s.handlePINVerify)

	// Scoped API tokens (Sanctum/Cloudflare-style abilities).
	r.With(s.Middleware, s.csrfGuard).Post("/api/auth/tokens", s.handleCreateToken)
	r.With(s.Middleware).Get("/api/auth/tokens", s.handleListTokens)
	r.With(s.Middleware, s.csrfGuard).Delete("/api/auth/tokens/{id}", s.handleRevokeToken)
}

// minPasswordLen is the enforced minimum (override via AUTH_MIN_PASSWORD).
func minPasswordLen() int {
	if v := os.Getenv("AUTH_MIN_PASSWORD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 8
}

// validatePassword enforces length policy (bcrypt caps input at 72 bytes).
func validatePassword(p string) error {
	if len(p) < minPasswordLen() {
		return errPolicy
	}
	if len(p) > 72 {
		return errTooLong
	}
	return nil
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Service) handleRegister(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if json.NewDecoder(r.Body).Decode(&c) != nil || c.Email == "" || c.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password required"})
		return
	}
	if err := validatePassword(c.Password); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	ctx := r.Context()
	if s.driver() == "supabase" {
		tok, err := supabaseSignup(ctx, c.Email, c.Password)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		s.startSession(w, ctx, tok)
		s.fire(ctx, EventRegistered, map[string]string{"email": c.Email})
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok})
		return
	}
	hash, err := hashPassword(c.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "registration failed"})
		return
	}
	u := User{ID: genID(), Email: c.Email, PasswordHash: hash, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := s.users().Create(ctx, map[string]any{
		"id": u.ID, "email": u.Email, "password_hash": u.PasswordHash,
		"roles": "", "permissions": "", "created_at": u.CreatedAt,
	}); err != nil {
		// Generic message — don't reveal whether the email already exists.
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "registration failed"})
		return
	}
	token, _ := s.IssueToken(*u.identity(s.def))
	s.startSession(w, ctx, token)
	s.fire(ctx, EventRegistered, u)
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "user": u})
}

// handleLogout clears the session cookie and revokes the server-side session.
func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.endSession(w, r)
	if id, ok := IdentityFrom(r.Context()); ok {
		s.fire(r.Context(), EventLogout, id)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var c credentials
	if json.NewDecoder(r.Body).Decode(&c) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	ctx := r.Context()
	if s.driver() == "supabase" {
		tok, err := supabaseLogin(ctx, c.Email, c.Password)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		s.startSession(w, ctx, tok)
		s.fire(ctx, EventLogin, map[string]string{"email": c.Email})
		writeJSON(w, http.StatusOK, map[string]any{"token": tok})
		return
	}
	id, err := s.Guard("").Auth.Attempt(ctx, c.Email, c.Password)
	if err != nil {
		s.fire(ctx, EventLoginFailed, map[string]string{"email": c.Email})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token, _ := s.IssueToken(*id)
	s.startSession(w, ctx, token)
	s.fire(ctx, EventLogin, id)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": id})
}

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	writeJSON(w, http.StatusOK, id)
}

func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Old string `json:"old_password"`
		New string `json:"new_password"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.New == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "old_password and new_password required"})
		return
	}
	if err := validatePassword(body.New); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	id, _ := IdentityFrom(r.Context())
	ctx := r.Context()
	u, err := s.users().Find(ctx, id.ID)
	if err != nil || u == nil || !checkPassword(u.PasswordHash, body.Old) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "current password incorrect"})
		return
	}
	hash, _ := hashPassword(body.New)
	if err := s.users().Where("id", "=", id.ID).Update(ctx, map[string]any{"password_hash": hash}); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}
	s.fire(ctx, EventPasswordChanged, id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func genID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
