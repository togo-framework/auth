package auth

import (
	"context"
	"net/http"
	"time"
)

// Exported helpers for external login drivers (OAuth, SAML, WorkOS, Firebase).
// A driver authenticates the user with its provider, resolves an email, then
// calls FindOrCreateByEmail + IssueSession to complete a togo session.

// IssueSession issues a JWT for id, sets the session cookie, and fires EventLogin.
// Returns the token (drivers may also redirect).
func (s *Service) IssueSession(w http.ResponseWriter, id Identity) (string, error) {
	token, err := s.IssueToken(id)
	if err != nil {
		return "", err
	}
	s.setSessionCookie(w, token)
	s.fire(context.Background(), EventLogin, id)
	return token, nil
}

// FindOrCreateByEmail returns the identity for email, creating a passwordless
// account if none exists (used by SSO/OAuth where there's no local password).
func (s *Service) FindOrCreateByEmail(ctx context.Context, email string) (*Identity, error) {
	u, err := s.users().Where("email", "=", email).First(ctx)
	if err != nil {
		return nil, err
	}
	if u != nil {
		return u.identity(s.def), nil
	}
	nu := User{ID: genID(), Email: email, PasswordHash: "!sso", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := s.users().Create(ctx, map[string]any{
		"id": nu.ID, "email": nu.Email, "password_hash": nu.PasswordHash,
		"roles": "", "permissions": "", "created_at": nu.CreatedAt,
	}); err != nil {
		return nil, err
	}
	s.fire(ctx, EventRegistered, nu)
	return nu.identity(s.def), nil
}
