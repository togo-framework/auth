package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
