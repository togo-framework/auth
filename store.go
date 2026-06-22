package auth

import (
	"context"
	"database/sql"
	"errors"
)

// ErrInvalidCredentials is returned when email/password don't match.
var ErrInvalidCredentials = errors.New("invalid credentials")

func (s *Service) sqlDB() *sql.DB {
	db, _ := s.k.SQL(context.Background())
	return db
}

func (u User) identity(guard string) *Identity {
	return &Identity{
		ID:          u.ID,
		Email:       u.Email,
		Roles:       splitCSV(u.Roles),
		Permissions: splitCSV(u.Permissions),
		Guard:       guard,
	}
}

// dbAuthenticator is the default guard: users table + bcrypt.
type dbAuthenticator struct{ s *Service }

func (d *dbAuthenticator) Attempt(ctx context.Context, email, password string) (*Identity, error) {
	u, err := d.s.users().Where("email", "=", email).First(ctx)
	if err != nil {
		return nil, err
	}
	if u == nil || !checkPassword(u.PasswordHash, password) {
		return nil, ErrInvalidCredentials
	}
	return u.identity("api"), nil
}

func (d *dbAuthenticator) ByID(ctx context.Context, id string) (*Identity, error) {
	u, err := d.s.users().Find(ctx, id)
	if err != nil || u == nil {
		return nil, err
	}
	return u.identity("api"), nil
}
