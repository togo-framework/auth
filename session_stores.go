package auth

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// --- database session store ----------------------------------------------

type dbSessionStore struct{ s *Service }

func (d *dbSessionStore) ensure() {}

func (s *Service) ensureSessionSchema(ctx context.Context) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_sessions (
		sid text PRIMARY KEY,
		token text NOT NULL,
		expires_at text NOT NULL
	)`)
	return err
}

func (d *dbSessionStore) Put(ctx context.Context, sid, token string, ttl time.Duration) error {
	db, err := d.s.k.SQL(ctx)
	if err != nil {
		return err
	}
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	p := d.s.ph
	q := "INSERT INTO auth_sessions (sid, token, expires_at) VALUES (" + //#nosec G202 -- dialect placeholders only; values parameterized
		p(1) + ", " + p(2) + ", " + p(3) + ") ON CONFLICT (sid) DO UPDATE SET token = " + p(2) + ", expires_at = " + p(3)
	_, err = db.ExecContext(ctx, q, sid, token, exp)
	return err
}

func (d *dbSessionStore) Get(ctx context.Context, sid string) (string, bool, error) {
	db, err := d.s.k.SQL(ctx)
	if err != nil {
		return "", false, err
	}
	var token, exp string
	//#nosec G202 -- dialect placeholder only; value parameterized
	if db.QueryRowContext(ctx, "SELECT token, expires_at FROM auth_sessions WHERE sid = "+d.s.ph(1), sid).Scan(&token, &exp) != nil {
		return "", false, nil
	}
	if t, err := time.Parse(time.RFC3339, exp); err != nil || time.Now().After(t) {
		_ = d.Delete(ctx, sid)
		return "", false, nil
	}
	return token, true, nil
}

func (d *dbSessionStore) Delete(ctx context.Context, sid string) error {
	db, err := d.s.k.SQL(ctx)
	if err != nil {
		return err
	}
	//#nosec G202 -- dialect placeholder only; value parameterized
	_, err = db.ExecContext(ctx, "DELETE FROM auth_sessions WHERE sid = "+d.s.ph(1), sid)
	return err
}

// --- file session store --------------------------------------------------

type fileSessionStore struct {
	dir string
	mu  sync.Mutex
}

func newFileSessionStore() *fileSessionStore {
	dir := os.Getenv("SESSION_DIR")
	if dir == "" {
		dir = "storage/sessions"
	}
	_ = os.MkdirAll(dir, 0o700) //#nosec G703,G301 -- dir is operator config (SESSION_DIR), not user input
	return &fileSessionStore{dir: dir}
}

func (f *fileSessionStore) path(sid string) string { return filepath.Join(f.dir, filepath.Base(sid)+".session") }

func (f *fileSessionStore) Put(_ context.Context, sid, token string, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp := time.Now().Add(ttl).UTC().Format(time.RFC3339)
	return os.WriteFile(f.path(sid), []byte(exp+"\n"+token), 0o600)
}

func (f *fileSessionStore) Get(ctx context.Context, sid string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, err := os.ReadFile(f.path(sid))
	if err != nil {
		return "", false, nil
	}
	exp, token, found := cut(string(b), "\n")
	if !found {
		return "", false, nil
	}
	if t, err := time.Parse(time.RFC3339, exp); err != nil || time.Now().After(t) {
		_ = os.Remove(f.path(sid))
		return "", false, nil
	}
	return token, true, nil
}

func (f *fileSessionStore) Delete(_ context.Context, sid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return os.Remove(f.path(sid))
}

func cut(s, sep string) (before, after string, found bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
