package auth

import (
	"net/http"
	"sync"
)

// LoginMethod is an alternative sign-in option (OAuth provider, dev login, SSO …)
// advertised to the frontend so it only renders methods that are actually
// configured. Plugins register theirs via RegisterLoginMethod.
type LoginMethod struct {
	Name  string `json:"name"`  // e.g. "google", "dev"
	Label string `json:"label"` // button text
	Type  string `json:"type"`  // "oauth" | "dev" | "sso"
	URL   string `json:"url"`   // endpoint to hit/redirect
}

var (
	lmMu         sync.RWMutex
	loginMethods []LoginMethod
)

// RegisterLoginMethod advertises a sign-in method (call from a plugin init/provider).
func RegisterLoginMethod(m LoginMethod) {
	lmMu.Lock()
	loginMethods = append(loginMethods, m)
	lmMu.Unlock()
}

func (s *Service) handleMethods(w http.ResponseWriter, r *http.Request) {
	lmMu.RLock()
	methods := append([]LoginMethod(nil), loginMethods...)
	lmMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"methods": methods})
}
