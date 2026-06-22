package auth

import (
	"context"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/togo-framework/togo"
)

// Session storage. The default "cookie" driver is stateless (the JWT lives in the
// cookie). Server-side drivers (database, file, redis) store the token under an
// opaque session id so sessions are revocable and listable. Redis ships as a
// plugin via RegisterSessionStore; cookie/database/file are built in.
//
// SESSION_DRIVER selects: cookie (default) | database | file | redis | ...

// SessionStore persists a token under a session id with a TTL.
type SessionStore interface {
	Put(ctx context.Context, sid, token string, ttl time.Duration) error
	Get(ctx context.Context, sid string) (string, bool, error)
	Delete(ctx context.Context, sid string) error
}

var (
	storeMu        sync.RWMutex
	storeFactories = map[string]func(k *togo.Kernel) (SessionStore, error){}
)

// RegisterSessionStore registers a server-side session driver (call from init()).
func RegisterSessionStore(name string, f func(k *togo.Kernel) (SessionStore, error)) {
	storeMu.Lock()
	storeFactories[name] = f
	storeMu.Unlock()
}

// initSessions wires the configured session store ("cookie" => stateless).
func (s *Service) initSessions() error {
	name := os.Getenv("SESSION_DRIVER")
	if name == "" {
		name = "cookie"
	}
	s.sessionDriver = name
	switch name {
	case "cookie":
		return nil // stateless: token lives in the cookie
	case "database":
		s.sessions = &dbSessionStore{s: s}
		return s.ensureSessionSchema(context.Background())
	case "file":
		s.sessions = newFileSessionStore()
		return nil
	default:
		storeMu.RLock()
		f, ok := storeFactories[name]
		storeMu.RUnlock()
		if !ok {
			return nil // unknown driver: fall back to stateless silently
		}
		store, err := f(s.k)
		if err != nil {
			return err
		}
		s.sessions = store
		return nil
	}
}

// startSession sets the session cookie. Server-side drivers store the token and
// put an opaque id in the cookie; the stateless driver puts the token directly.
func (s *Service) startSession(w http.ResponseWriter, ctx context.Context, token string) {
	if s.sessions == nil {
		s.setSessionCookie(w, token)
		return
	}
	sid := genID() + genID()
	if err := s.sessions.Put(ctx, sid, token, s.ttl); err != nil {
		s.setSessionCookie(w, token) // degrade to stateless on store failure
		return
	}
	s.setSessionCookie(w, sid)
}

// endSession clears the cookie and deletes the server-side record (if any).
func (s *Service) endSession(w http.ResponseWriter, r *http.Request) {
	if s.sessions != nil {
		if c, err := r.Cookie(SessionCookie); err == nil {
			_ = s.sessions.Delete(r.Context(), c.Value)
		}
	}
	s.clearSessionCookie(w)
}

// resolveToken returns the JWT from the bearer header, or the cookie (resolving
// the session id through the store for server-side drivers).
func (s *Service) resolveToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
		return trimToken(h[7:])
	}
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	if s.sessions == nil {
		return c.Value // stateless: cookie holds the token
	}
	token, ok, err := s.sessions.Get(r.Context(), c.Value)
	if err != nil || !ok {
		return ""
	}
	return token
}

func trimToken(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	return s
}
