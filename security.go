package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// ---- CORS ----------------------------------------------------------------

// cors applies a configurable, credential-aware CORS policy. Origins come from
// CORS_ORIGINS (comma-separated; "*" allows all). Empty = same-origin only
// (cross-origin blocked), which is the secure default.
func (s *Service) cors(next http.Handler) http.Handler {
	origins := splitCSV(os.Getenv("CORS_ORIGINS"))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && originAllowed(origins, origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func originAllowed(list []string, origin string) bool {
	for _, a := range list {
		if a == "*" || a == origin {
			return true
		}
	}
	return false
}

// ---- Rate limiting -------------------------------------------------------

type rateLimiter struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{hits: map[string][]time.Time{}, max: max, window: window}
}

func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cut := now.Add(-rl.window)
	kept := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= rl.max {
		rl.hits[key] = kept
		return false
	}
	rl.hits[key] = append(kept, now)
	return true
}

// limit wraps a handler with per-IP rate limiting (anti-brute-force).
func (rl *rateLimiter) limit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.window.Seconds())))
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
			return
		}
		next(w, r)
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := indexByte(xff, ','); i >= 0 {
			return trimSpace(xff[:i])
		}
		return trimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- CSRF (double-submit cookie) ----------------------------------------

const csrfCookie = "togo_csrf"

// issueCSRF sets a CSRF cookie and returns its token (for cookie/SSR clients).
func (s *Service) issueCSRF(w http.ResponseWriter, r *http.Request) {
	tok := randomToken()
	// Not HttpOnly by design: the double-submit pattern requires JS to read this
	// token and echo it in the X-CSRF-Token header. Secure is env-driven.
	http.SetCookie(w, &http.Cookie{ //#nosec G124 -- CSRF token must be JS-readable (double-submit); env-driven Secure
		Name: csrfCookie, Value: tok, Path: "/",
		Secure: secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": tok})
}

// csrfGuard enforces double-submit CSRF on unsafe methods for COOKIE-authed
// requests. Bearer-token (API) requests are exempt (not CSRF-prone).
func (s *Service) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		// Bearer requests aren't cookie-driven → no CSRF risk.
		if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(csrfCookie)
		header := r.Header.Get("X-CSRF-Token")
		if err != nil || header == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(header)) != 1 {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid csrf token"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ---- session cookie ------------------------------------------------------

func (s *Service) setSessionCookie(w http.ResponseWriter, token string) {
	// HttpOnly + SameSite always set; Secure is env-driven (true in production).
	http.SetCookie(w, &http.Cookie{ //#nosec G124 -- HttpOnly+SameSite enforced; Secure is environment-driven
		Name: SessionCookie, Value: token, Path: "/",
		HttpOnly: true, Secure: secureCookies(), SameSite: http.SameSiteLaxMode,
		MaxAge: int(s.ttl.Seconds()),
	})
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //#nosec G124 -- HttpOnly+SameSite enforced; Secure is environment-driven
		Name: SessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: secureCookies(), SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// secureCookies returns true in production (HTTPS-only cookies).
func secureCookies() bool {
	if v := os.Getenv("COOKIE_SECURE"); v != "" {
		return v == "1" || v == "true"
	}
	return isProduction()
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// tiny string helpers (avoid importing strings twice across files)
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
