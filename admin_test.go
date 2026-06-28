package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/togo-framework/togo"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver for tests
)

// newTestService builds a Service backed by a fresh in-memory SQLite DB and the
// real admin routes mounted on a chi router. An admin bearer token is returned
// for authenticating against the guarded /api/auth/admin/* surface.
func newTestService(t *testing.T) (*Service, chi.Router, string) {
	t.Helper()
	dsn := fmt.Sprintf("file:authadmin_%d?mode=memory&cache=shared", time.Now().UnixNano())
	k := &togo.Kernel{
		Config: &togo.Config{DBDriver: "sqlite", DatabaseURL: dsn},
		Router: chi.NewMux(),
	}
	s := &Service{
		k:      k,
		secret: []byte("a-sufficiently-long-test-secret-string!!"),
		ttl:    time.Hour,
		guards: map[string]*Guard{},
		def:    "api",
	}
	s.RegisterGuard("api", &dbAuthenticator{s: s})
	if err := s.ensureSchema(context.Background()); err != nil {
		t.Fatalf("ensureSchema: %v", err)
	}
	if err := s.ensurePATSchema(context.Background()); err != nil {
		t.Fatalf("ensurePATSchema: %v", err)
	}
	s.mountAdminRoutes(k.Router)
	// An admin caller (its identity carries the admin role for RequireRole).
	adminTok, err := s.IssueToken(Identity{ID: "admin-caller", Email: "root@togo.dev", Roles: []string{"admin"}, Guard: "api"})
	if err != nil {
		t.Fatalf("issue admin token: %v", err)
	}
	return s, k.Router, adminTok
}

func do(t *testing.T, r chi.Router, method, path, bearer string, body any) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestAdminCreateListDelete(t *testing.T) {
	s, r, admin := newTestService(t)

	// create
	rec, out := do(t, r, http.MethodPost, "/api/auth/admin/users", admin, map[string]any{
		"email": "Alice@Example.com", "password": "supersecret123", "roles": []string{"editor"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201 got %d body=%s", rec.Code, rec.Body.String())
	}
	u, _ := out["user"].(map[string]any)
	if u["email"] != "alice@example.com" {
		t.Fatalf("email not normalized: %v", u["email"])
	}
	id, _ := u["id"].(string)
	if id == "" {
		t.Fatal("created user has no id")
	}

	// the created password must authenticate via the same guard login uses
	if _, err := s.Guard("").Auth.Attempt(context.Background(), "alice@example.com", "supersecret123"); err != nil {
		t.Fatalf("created password does not authenticate: %v", err)
	}

	// duplicate create → 409
	if rec2, _ := do(t, r, http.MethodPost, "/api/auth/admin/users", admin, map[string]any{"email": "alice@example.com"}); rec2.Code != http.StatusConflict {
		t.Fatalf("duplicate: want 409 got %d", rec2.Code)
	}

	// list
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/api/auth/admin/users", nil)
	req3.Header.Set("Authorization", "Bearer "+admin)
	r.ServeHTTP(rec3, req3)
	var list []adminUser
	if err := json.Unmarshal(rec3.Body.Bytes(), &list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if len(list) != 1 || list[0].Email != "alice@example.com" {
		t.Fatalf("list mismatch: %+v", list)
	}

	// delete
	if rec4, _ := do(t, r, http.MethodDelete, "/api/auth/admin/users/"+id, admin, nil); rec4.Code != http.StatusOK {
		t.Fatalf("delete: want 200 got %d", rec4.Code)
	}
	rec5 := httptest.NewRecorder()
	req5 := httptest.NewRequest(http.MethodGet, "/api/auth/admin/users", nil)
	req5.Header.Set("Authorization", "Bearer "+admin)
	r.ServeHTTP(rec5, req5)
	var after []adminUser
	_ = json.Unmarshal(rec5.Body.Bytes(), &after)
	if len(after) != 0 {
		t.Fatalf("user not deleted: %+v", after)
	}
}

func TestAdminDeleteLastAdminRefused(t *testing.T) {
	_, r, admin := newTestService(t)
	rec, out := do(t, r, http.MethodPost, "/api/auth/admin/users", admin, map[string]any{
		"email": "boss@example.com", "roles": []string{"admin"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create admin: %d", rec.Code)
	}
	id := out["user"].(map[string]any)["id"].(string)
	if rec2, _ := do(t, r, http.MethodDelete, "/api/auth/admin/users/"+id, admin, nil); rec2.Code != http.StatusConflict {
		t.Fatalf("delete last admin: want 409 got %d", rec2.Code)
	}
}

func TestAdminImpersonateTokenVerifies(t *testing.T) {
	s, r, admin := newTestService(t)
	_, out := do(t, r, http.MethodPost, "/api/auth/admin/users", admin, map[string]any{
		"email": "target@example.com", "roles": []string{"editor"}, "permissions": []string{"posts.write"},
	})
	id := out["user"].(map[string]any)["id"].(string)

	rec, imp := do(t, r, http.MethodPost, "/api/auth/admin/users/"+id+"/impersonate", admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("impersonate: want 200 got %d", rec.Code)
	}
	tok, _ := imp["token"].(string)
	identity, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("impersonation token does not verify: %v", err)
	}
	if identity.ID != id || identity.Email != "target@example.com" || !identity.HasRole("editor") || !identity.Can("posts.write") {
		t.Fatalf("impersonation identity mismatch: %+v", identity)
	}
}

func TestAdminMagicLinkRoundTrip(t *testing.T) {
	_, r, admin := newTestService(t)
	_, out := do(t, r, http.MethodPost, "/api/auth/admin/users", admin, map[string]any{"email": "magic@example.com"})
	id := out["user"].(map[string]any)["id"].(string)

	rec, link := do(t, r, http.MethodPost, "/api/auth/admin/users/"+id+"/magic-link", admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("magic-link: want 200 got %d", rec.Code)
	}
	if link["emailed"] != false {
		t.Fatalf("emailed should be false with no mailer: %v", link["emailed"])
	}
	linkURL, _ := link["link"].(string)
	if linkURL == "" {
		t.Fatal("no link returned")
	}
	// Consume the link: it should issue a session cookie and redirect.
	req := httptest.NewRequest(http.MethodGet, linkURL, nil)
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusFound {
		t.Fatalf("magic consume: want 302 got %d body=%s", rec2.Code, rec2.Body.String())
	}
	var sessionSet bool
	for _, c := range rec2.Result().Cookies() {
		if c.Name == SessionCookie && c.Value != "" {
			sessionSet = true
		}
	}
	if !sessionSet {
		t.Fatal("magic consume did not set a session cookie")
	}

	// A tampered token must be rejected.
	bad := httptest.NewRequest(http.MethodGet, "/api/auth/magic?token=deadbeef.deadbeef", nil)
	recBad := httptest.NewRecorder()
	r.ServeHTTP(recBad, bad)
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("tampered token: want 401 got %d", recBad.Code)
	}
}

func TestAdminRequiresAdminRole(t *testing.T) {
	s, r, _ := newTestService(t)
	// A non-admin bearer is forbidden.
	plain, _ := s.IssueToken(Identity{ID: "u9", Email: "nobody@example.com", Roles: []string{"editor"}, Guard: "api"})
	if rec, _ := do(t, r, http.MethodGet, "/api/auth/admin/users", plain, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin: want 403 got %d", rec.Code)
	}
	// No token at all is unauthorized.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/auth/admin/users", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon: want 401 got %d", rec.Code)
	}
}
