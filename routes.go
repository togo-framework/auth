package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

// driver selects the auth backend: "base" (DB + JWT, default) or "supabase".
func (s *Service) driver() string {
	if d := os.Getenv("AUTH_DRIVER"); d != "" {
		return d
	}
	return "base"
}

// mountRoutes registers /api/auth/* on the kernel router. Designed so Supabase/
// GoTrue is first-class (AUTH_DRIVER=supabase) and other backends drop in as
// driver plugins.
func (s *Service) mountRoutes() {
	r := s.k.Router
	r.Post("/api/auth/register", s.handleRegister)
	r.Post("/api/auth/login", s.handleLogin)
	r.With(s.Middleware).Get("/api/auth/me", s.handleMe)
	r.With(s.Middleware).Post("/api/auth/change-password", s.handleChangePassword)
	// Endpoints the frontend auth suite calls; full flows land incrementally.
	for _, p := range []string{"reset", "otp", "2fa", "pin", "logout"} {
		p := p
		r.Post("/api/auth/"+p, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusNotImplemented, map[string]string{"error": p + " not implemented yet"})
		})
	}
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
	ctx := r.Context()
	if s.driver() == "supabase" {
		tok, err := supabaseSignup(ctx, c.Email, c.Password)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"token": tok})
		return
	}
	hash, err := hashPassword(c.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash failed"})
		return
	}
	u := User{ID: genID(), Email: c.Email, PasswordHash: hash, CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := s.users().Create(ctx, map[string]any{
		"id": u.ID, "email": u.Email, "password_hash": u.PasswordHash,
		"roles": "", "permissions": "", "created_at": u.CreatedAt,
	}); err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "could not create user (email taken?)"})
		return
	}
	token, _ := s.IssueToken(*u.identity(s.def))
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "user": u})
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
		writeJSON(w, http.StatusOK, map[string]any{"token": tok})
		return
	}
	id, err := s.Guard("").Auth.Attempt(ctx, c.Email, c.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	token, _ := s.IssueToken(*id)
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func genID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
