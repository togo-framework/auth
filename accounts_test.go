package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountHelpers(t *testing.T) {
	_, svc := bootAuth(t)
	ctx := context.Background()

	id, err := svc.CreateUser(ctx, "ops@example.com", "correct-horse-battery", []string{"operations"})
	if err != nil || !id.HasRole("operations") {
		t.Fatalf("create = %+v %v", id, err)
	}
	if _, err := svc.CreateUser(ctx, "weak@example.com", "short", nil); err == nil {
		t.Fatal("the password policy must apply to CreateUser")
	}

	if err := svc.SetRoles(ctx, id.ID, []string{"admin", " ", "bad,role"}); err != nil {
		t.Fatal(err)
	}
	fresh, err := svc.UserByID(ctx, id.ID)
	if err != nil || len(fresh.Roles) != 1 || !fresh.HasRole("admin") {
		t.Fatalf("roles after SetRoles = %+v %v", fresh, err)
	}
	if err := svc.SetRoles(ctx, "nobody", []string{"admin"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}

	// Authenticate resolves a bearer token and reports, rather than answers, a miss.
	token, _ := svc.IssueToken(*fresh)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if got, err := svc.Authenticate(req); err != nil || got.ID != id.ID {
		t.Fatalf("authenticate = %+v %v", got, err)
	}
	if _, err := svc.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatal("an anonymous request must not authenticate")
	}
}

func TestSetPassword(t *testing.T) {
	_, svc := bootAuth(t)
	ctx := context.Background()
	id, err := svc.CreateUser(ctx, "reset@example.com", "original-password-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetPassword(ctx, id.ID, "short"); err == nil {
		t.Fatal("the password policy must apply")
	}
	if err := svc.SetPassword(ctx, id.ID, "brand-new-password-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Guard("").Auth.Attempt(ctx, "reset@example.com", "original-password-1"); err == nil {
		t.Fatal("the old password must stop working")
	}
	if _, err := svc.Guard("").Auth.Attempt(ctx, "reset@example.com", "brand-new-password-2"); err != nil {
		t.Fatalf("the new password should work: %v", err)
	}
	if err := svc.SetPassword(ctx, "nobody", "brand-new-password-2"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestCSRFSparesNativeClientsNotBrowsers(t *testing.T) {
	srv, svc := bootAuth(t)
	ctx := context.Background()
	if _, err := svc.CreateUser(ctx, "native@example.com", "native-password-1", nil); err != nil {
		t.Fatal(err)
	}
	post := func(headers map[string]string) int {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/auth/login", strings.NewReader(`{"email":"native@example.com","password":"native-password-1"}`))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := post(nil); code != http.StatusOK {
		t.Fatalf("a native client (no cookies, no Origin) should sign in, got %d", code)
	}
	if code := post(map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("SECURITY: a cross-site browser POST must still need the token, got %d", code)
	}
	if code := post(map[string]string{"Cookie": "togo_session=x"}); code != http.StatusForbidden {
		t.Fatalf("SECURITY: a cookie-carrying request must still need the token, got %d", code)
	}
}
