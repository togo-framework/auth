package auth

import (
	"context"
	"strings"
	"testing"
)

// F-R6-1: an admin-issued credential carries issuer-authority context. When the
// issuer is deleted or demoted while the credential is outstanding, redemption
// is refused exactly like an unknown credential, and the credential stays burned.

func r6IssueAs(t *testing.T, w *reviewWorld, tok, kind, id string) string {
	t.Helper()
	c, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+id+"/"+kind, tok, map[string]string{})
	l, _ := asMap(t, b)["link"].(string)
	i := strings.Index(l, "token=")
	if c != 200 || i < 0 {
		t.Fatalf("issue %s => %d", kind, c)
	}
	return l[i+6:]
}

func r6Redeem(t *testing.T, w *reviewWorld, kind, tok string) (int, string) {
	t.Helper()
	if kind == "reset-password" {
		c, b, _ := raw(t, w.srv, "POST", "/api/auth/password/reset", "", map[string]string{"token": tok, "password": "Issuer-gone-pw-1"})
		return c, string(b)
	}
	c, b, _ := raw(t, w.srv, "GET", "/api/auth/magic?token="+tok, "", nil)
	return c, string(b)
}

func TestR6IssuerGoneRefusedLikeUnknownAndBurned(t *testing.T) {
	unknown := "deadbeef" + strings.Repeat("0", 56)
	for _, kind := range []string{"reset-password", "magic-link"} {
		for _, how := range []string{"deleted", "demoted"} {
			kind, how := kind, how
			t.Run(kind+"/"+how, func(t *testing.T) {
				w := newReviewWorld(t)
				ctx := context.Background()
				issuerID, issuerTok := w.secondAdmin(t)
				tok := r6IssueAs(t, w, issuerTok, kind, w.userID)
				wantC, wantB := r6Redeem(t, w, kind, unknown)
				switch how {
				case "deleted":
					db, _ := w.svc.k.SQL(ctx)
					if _, err := db.Exec("DELETE FROM users WHERE id = "+w.svc.ph(1), issuerID); err != nil {
						t.Fatal(err)
					}
				case "demoted":
					if err := w.svc.SetRoles(ctx, issuerID, nil); err != nil {
						t.Fatal(err)
					}
				}
				if c, b := r6Redeem(t, w, kind, tok); c != wantC || b != wantB {
					t.Fatalf("refusal differs from unknown credential: %d %q vs %d %q", c, b, wantC, wantB)
				}
				if kind == "reset-password" {
					if loginCode(t, w, "bob@example.com", "Issuer-gone-pw-1") == 200 {
						t.Fatal("password was changed by a credential whose issuer is gone")
					}
				}
				if how == "demoted" {
					// Restoring the issuer must not resurrect the burned credential.
					if err := w.svc.SetRoles(ctx, issuerID, []string{"admin"}); err != nil {
						t.Fatal(err)
					}
					if c, b := r6Redeem(t, w, kind, tok); c != wantC || b != wantB {
						t.Fatalf("burned credential replayed after restore: %d %q", c, b)
					}
					if kind == "reset-password" && loginCode(t, w, "bob@example.com", "Issuer-gone-pw-1") == 200 {
						t.Fatal("replay after restore changed the password")
					}
				}
			})
		}
	}
}
