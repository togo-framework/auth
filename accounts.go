package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Authenticate resolves the request's identity (bearer JWT, personal access
// token, or session cookie) without writing a response. Apps that layer their
// own policy on top of auth — public and protected routes on one router, or
// roles mapped to app actors — use it instead of Middleware, which answers 401.
func (s *Service) Authenticate(r *http.Request) (*Identity, error) {
	return s.authenticate(r)
}

// UserByID loads an account's current identity from the store. Roles and
// permissions in a JWT are a snapshot from sign-in; apps that must honour a
// role change or revocation immediately re-read them here.
func (s *Service) UserByID(ctx context.Context, id string) (*Identity, error) {
	u, err := s.users().Find(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	return u.identity(s.def), nil
}

// ErrUserNotFound is returned when an account operation names no account.
var ErrUserNotFound = errors.New("user not found")

// SetRoles replaces an account's roles. Registration creates accounts with no
// roles, so this is how an app grants them (an admin screen, a seeder, or a
// bootstrap step).
func (s *Service) SetRoles(ctx context.Context, userID string, roles []string) error {
	clean := make([]string, 0, len(roles))
	for _, r := range roles {
		if r = strings.TrimSpace(r); r != "" && !strings.Contains(r, ",") {
			clean = append(clean, r)
		}
	}
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, `UPDATE users SET roles = `+s.ph(1)+` WHERE id = `+s.ph(2), strings.Join(clean, ","), userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	return nil
}

// CreateUser adds an account with a password and roles, for seeders and
// bootstrap steps that must not go through public registration. It fires
// EventRegistered like registration does.
func (s *Service) CreateUser(ctx context.Context, email, password string, roles []string) (*Identity, error) {
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}
	u := User{ID: genID(), Email: strings.TrimSpace(email), PasswordHash: hash, Roles: strings.Join(roles, ","), CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if _, err := s.users().Create(ctx, map[string]any{
		"id": u.ID, "email": u.Email, "password_hash": u.PasswordHash,
		"roles": u.Roles, "permissions": "", "created_at": u.CreatedAt,
	}); err != nil {
		return nil, err
	}
	s.fire(ctx, EventRegistered, u)
	return u.identity(s.def), nil
}

// SetPassword replaces an account's password, for an admin resetting a user
// who cannot receive a reset link. The password policy applies, and
// EventPasswordChanged fires as it does for a self-service change.
func (s *Service) SetPassword(ctx context.Context, userID, password string) error {
	if err := validatePassword(password); err != nil {
		return err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	res, err := db.ExecContext(ctx, `UPDATE users SET password_hash = `+s.ph(1)+` WHERE id = `+s.ph(2), hash, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrUserNotFound
	}
	s.fire(ctx, EventPasswordChanged, map[string]string{"user_id": userID, "by": "admin"})
	return nil
}
