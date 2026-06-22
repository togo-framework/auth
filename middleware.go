package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type ctxKey struct{}

// Middleware authenticates the request from its bearer token and stores the
// Identity in context. 401 if the token is missing/invalid.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.Verify(bearer(r))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

// RequireRole guards a route by role.
func (s *Service) RequireRole(role string) func(http.Handler) http.Handler {
	return s.guardBy(func(id *Identity) bool { return id.HasRole(role) })
}

// RequirePermission guards a route by permission.
func (s *Service) RequirePermission(perm string) func(http.Handler) http.Handler {
	return s.guardBy(func(id *Identity) bool { return id.Can(perm) })
}

func (s *Service) guardBy(ok func(*Identity) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return s.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, _ := IdentityFrom(r.Context())
			if id == nil || !ok(id) {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// IdentityFrom returns the authenticated identity from the request context.
func IdentityFrom(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(*Identity)
	return id, ok
}

func bearer(r *http.Request) string {
	return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
