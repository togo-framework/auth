package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestValidEmail(t *testing.T) {
	for email, want := range map[string]bool{
		"a@b.co":          true,
		"first.last@x.io": true,
		"bad":             false,
		"a@b":             false,
		"@b.co":           false,
		"Fady <a@b.co>":   false,
		"<a@b.co>":        false,
		"a@b.co, c@d.co":  false,
	} {
		if got := validEmail(email); got != want {
			t.Errorf("validEmail(%q) = %v, want %v", email, got, want)
		}
	}
}

func TestEmailIsCaseInsensitive(t *testing.T) {
	srv, _ := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "  Mixed@Example.COM ")

	for _, email := range []string{"mixed@example.com", "MIXED@EXAMPLE.COM", " Mixed@Example.com"} {
		if code := c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": pw}, nil); code != http.StatusOK {
			t.Errorf("login as %q: %d, want 200", email, code)
		}
	}
	if code := c.do(http.MethodPost, "/api/auth/register", map[string]string{"email": "mixed@example.com", "password": pw}, nil); code == http.StatusCreated {
		t.Error("a second account differing only in case was created")
	}
}

func TestRegisterRejectsInvalidEmail(t *testing.T) {
	srv, _ := bootAuth(t)
	c := newClient(t, srv)
	for _, email := range []string{"bad", "a@b", "Name <a@b.co>"} {
		if code := c.do(http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": pw}, nil); code != http.StatusUnprocessableEntity {
			t.Errorf("register %q: %d, want 422", email, code)
		}
	}
}

// Accounts stored before normalisation keep their casing and must still sign in.
func TestLegacyMixedCaseAccountStillSignsIn(t *testing.T) {
	srv, svc := bootAuth(t)
	c := newClient(t, srv)
	hash, err := hashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.users().Create(context.Background(), map[string]any{
		"id": genID(), "email": "Legacy@Example.com", "password_hash": hash,
		"roles": "", "permissions": "", "created_at": time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	if code := c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "Legacy@Example.com", "password": pw}, nil); code != http.StatusOK {
		t.Fatalf("legacy login: %d, want 200", code)
	}
}
