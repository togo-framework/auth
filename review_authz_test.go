package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

// ---- (1) route enumeration: nothing privileged outside requireAdmin ---------

func TestReviewEveryAdminRouteIsDefaultDenied(t *testing.T) {
	w := newReviewWorld(t)
	var routes []string
	err := chi.Walk(w.svc.k.Router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		routes = append(routes, method+" "+route)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	privileged := 0
	for _, r := range routes {
		parts := strings.SplitN(r, " ", 2)
		method, route := parts[0], strings.ReplaceAll(parts[1], "{id}", w.userID)
		route = strings.TrimSuffix(route, "/*")
		low := strings.ToLower(route)
		if strings.Contains(low, "admin") || strings.Contains(low, "impersonat") {
			// Everything that mentions admin/impersonation must be under /api/auth/admin
			// (requireAdmin) or be the documented token-gated stop endpoint.
			if !strings.HasPrefix(route, "/api/auth/admin") && route != "/api/auth/impersonation/stop" {
				t.Errorf("privileged-looking route mounted outside requireAdmin: %s", r)
				continue
			}
		}
		if !strings.HasPrefix(route, "/api/auth/admin") {
			continue
		}
		privileged++
		if code, _, _ := raw(t, w.srv, method, route, "", map[string]string{}); code != http.StatusUnauthorized {
			t.Errorf("anonymous %s: want 401 got %d", r, code)
		}
		if code, b, _ := raw(t, w.srv, method, route, w.userTok, map[string]string{}); code != http.StatusForbidden {
			t.Errorf("SECURITY normal user %s: want 403 got %d %s", r, code, b)
		}
	}
	if privileged < 8 {
		t.Fatalf("expected at least 8 admin routes, walked %d: %v", privileged, routes)
	}
}

// Path/method confusion: none of these may return 2xx to an anonymous caller or a
// normal user.
func TestReviewAdminPathAndMethodConfusion(t *testing.T) {
	w := newReviewWorld(t)
	base := "/api/auth/admin/users"
	paths := []string{
		base + "/", base + "//", "/api/auth/admin", "/api/auth/admin/", "/api/auth//admin/users",
		"/api/auth/%61dmin/users", "/api/auth/admin/%75sers", "/api/auth/./admin/users",
		"/api/auth/x/../admin/users", "/api/auth/admin/users;x=1", "/API/AUTH/ADMIN/USERS",
		base + "/" + w.userID + "/", base + "/" + w.userID + "/IMPERSONATE",
		base + "/" + w.userID + "/impersonate/", base + "/..%2f" + w.userID,
		"/api/auth/admin/users?id=" + w.userID,
	}
	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "FOO"}
	for _, p := range paths {
		for _, m := range methods {
			for name, tok := range map[string]string{"anon": "", "user": w.userTok} {
				code, b, _ := raw(t, w.srv, m, p, tok, map[string]string{})
				if code >= 200 && code < 300 && m != "OPTIONS" {
					t.Errorf("SECURITY %s %s %s => %d %.120s", name, m, p, code, b)
				}
			}
		}
	}
}

// ---- (1b) other drivers / config combinations -------------------------------

func TestReviewNothingPrivilegedMountedOnOtherDrivers(t *testing.T) {
	for _, drv := range []string{"supabase", "BASE", "Base", "ldap", "base "} {
		t.Run(drv, func(t *testing.T) {
			t.Setenv("AUTH_DRIVER", drv)
			t.Setenv("SUPABASE_URL", "http://127.0.0.1:1")
			t.Setenv("SUPABASE_ANON_KEY", "x")
			srv, svc, _ := bootReview(t)
			var hits []string
			_ = chi.Walk(svc.k.Router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
				l := strings.ToLower(route)
				if strings.Contains(l, "admin") || strings.Contains(l, "magic") || strings.Contains(l, "impersonat") {
					hits = append(hits, method+" "+route)
				}
				return nil
			})
			if len(hits) != 0 {
				t.Errorf("driver %q mounts privileged routes: %v", drv, hits)
			}
			for _, p := range []string{"/api/auth/admin/users", "/api/auth/magic?token=x", "/api/auth/impersonation/stop"} {
				for _, m := range []string{"GET", "POST"} {
					if code, _, _ := raw(t, srv, m, p, "", map[string]string{}); code >= 200 && code < 300 {
						t.Errorf("driver %q %s %s => %d", drv, m, p, code)
					}
				}
			}
		})
	}
}

// ---- (2) revalidation against the DB; claim tampering -----------------------

func signWith(t *testing.T, key any, method jwt.SigningMethod, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func claimsFor(id, roles string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{"sub": id, "email": "x@example.com", "roles": roles, "perms": "", "guard": "api",
		"iss": "togo", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix()}
}

func TestReviewRoleClaimTampering(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	list := "/api/auth/admin/users"
	// Validly signed (server key) token that CLAIMS admin for a non-admin account:
	// the database, not the claim, decides.
	if code, _, _ := raw(t, w.srv, "GET", list, signWith(t, w.svc.secret, jwt.SigningMethodHS256, claimsFor(w.userID, "admin")), nil); code != 403 {
		t.Errorf("SECURITY claim-only admin got %d, want 403", code)
	}
	mut := func(f func(c jwt.MapClaims)) jwt.MapClaims { c := claimsFor(w.adminID, "admin"); f(c); return c }
	cases := map[string]string{
		"wrong key":   signWith(t, []byte("not-the-server-secret-not-the-server-secret"), jwt.SigningMethodHS256, claimsFor(w.adminID, "admin")),
		"hs512":       signWith(t, w.svc.secret, jwt.SigningMethodHS512, claimsFor(w.adminID, "admin")),
		"expired":     signWith(t, w.svc.secret, jwt.SigningMethodHS256, mut(func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() })),
		"no exp":      signWith(t, w.svc.secret, jwt.SigningMethodHS256, mut(func(c jwt.MapClaims) { delete(c, "exp") })),
		"wrong iss":   signWith(t, w.svc.secret, jwt.SigningMethodHS256, mut(func(c jwt.MapClaims) { c["iss"] = "evil" })),
		"alg none":    signWith(t, jwt.UnsafeAllowNoneSignatureType, jwt.SigningMethodNone, claimsFor(w.adminID, "admin")),
		"empty sub":   signWith(t, w.svc.secret, jwt.SigningMethodHS256, claimsFor("", "admin")),
		"unknown sub": signWith(t, w.svc.secret, jwt.SigningMethodHS256, claimsFor("does-not-exist", "admin")),
		"sub inject":  signWith(t, w.svc.secret, jwt.SigningMethodHS256, claimsFor(w.userID+"\x27 OR \x271\x27=\x271", "admin")),
	}
	for name, tok := range cases {
		if code, _, _ := raw(t, w.srv, "GET", list, tok, nil); code != 401 && code != 403 {
			t.Errorf("SECURITY %s: got %d", name, code)
		}
	}
	// Only the exact role "admin" counts.
	for i, role := range []string{"Admin", "ADMIN", "superadmin", "admin2", "administrator", "root", "admin​"} {
		email := "role" + strconv.Itoa(i) + "@example.com"
		if _, err := w.svc.CreateUser(ctx, email, pw, []string{role}); err != nil {
			t.Fatal(err)
		}
		tok := tokFor(t, w.svc, email)
		if code, _, _ := raw(t, w.srv, "GET", list, tok, nil); code != 403 {
			t.Errorf("SECURITY role %q reached the admin API: %d", role, code)
		}
	}
	// Mass assignment on public sign-up: roles/permissions/id in the body are ignored.
	code, b, _ := raw(t, w.srv, "POST", "/api/auth/register", "", map[string]any{
		"email": "mallory@example.com", "password": pw, "roles": []string{"admin"}, "role": "admin", "id": w.adminID, "permissions": []string{"*"}})
	if code != 201 {
		t.Fatalf("register: %d %s", code, b)
	}
	tok := tokFor(t, w.svc, "mallory@example.com")
	if code, _, _ := raw(t, w.srv, "GET", list, tok, nil); code != 403 {
		t.Errorf("SECURITY mass assignment at sign-up produced an admin: %d", code)
	}
}

// ---- (3) 401 vs 403 ----------------------------------------------------------

func TestReviewStatusCodes(t *testing.T) {
	w := newReviewWorld(t)
	u := "/api/auth/admin/users"
	cookieOnly := func(tok string) int {
		req, _ := http.NewRequest("GET", w.srv.URL+u, nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := cookieOnly(""); c != 401 {
		t.Errorf("empty cookie: %d", c)
	}
	if c := cookieOnly(w.userTok); c != 403 {
		t.Errorf("user cookie: %d", c)
	}
	if c := cookieOnly(w.adminTok); c != 200 {
		t.Errorf("admin cookie: %d", c)
	}
	for _, h := range []string{"Bearer", "Bearer ", "bearer " + w.adminTok, "Basic " + w.adminTok, w.adminTok} {
		req, _ := http.NewRequest("GET", w.srv.URL+u, nil)
		req.Header.Set("Authorization", h)
		res, _ := http.DefaultClient.Do(req)
		res.Body.Close()
		if res.StatusCode == 200 {
			t.Errorf("SECURITY odd Authorization %q accepted", h)
		}
	}
}
