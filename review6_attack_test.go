package auth

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Round 6 independent adversarial tests. Every test asserts the SAFE outcome;
// a failure is a finding.

func r6A(t *testing.T, w *reviewWorld) (id, tok string) {
	t.Helper()
	a, err := w.svc.CreateUser(context.Background(), "evil-a@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	return a.ID, tokFor(t, w.svc, "evil-a@example.com")
}

func r6Patch(t *testing.T, w *reviewWorld, tok, id, body string) int {
	return api(t, w, "PATCH", "/api/auth/admin/users/"+id, tok, body)
}

// A cannot end up admin-U-authenticated by any of: email A->C->A, case-only, A->Y->A.
func TestR6EmailRoundTripsNeverReleaseTaint(t *testing.T) {
	for _, name := range []string{"A-Y-A", "A-C-A", "case-only"} {
		t.Run(name, func(t *testing.T) {
			w := newReviewWorld(t)
			aID, aTok := r6A(t, w)
			_ = aID
			mail := r5Mailbox(w)
			if c := r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox@example.com"}`); c != 200 {
				t.Fatal(c)
			}
			tk := r5Forgot(t, w, mail, "a-inbox@example.com")
			switch name {
			case "A-Y-A":
				r6Patch(t, w, aTok, w.userID, `{"email":"y@example.com"}`)
				r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox@example.com"}`)
			case "A-C-A":
				r6Patch(t, w, w.adminTok, w.userID, `{"email":"y@example.com"}`)
				r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox@example.com"}`)
			case "case-only":
				// normalised, so a no-op; token must keep meaning "A's inbox"
				r6Patch(t, w, w.adminTok, w.userID, `{"email":"A-Inbox@Example.com"}`)
			}
			// whatever the token state, a promotion without accept must be 409
			if c, _ := w.promote(t, w.adminTok, w.userID, ``); c != 409 {
				t.Fatalf("promotion after %s => %d, want 409", name, c)
			}
			// redeem (may be 200 or 401), then promotion still 409
			_ = redeemReset(t, w, tk, "A-knows-this-pw-1")
			if c, _ := w.promote(t, w.adminTok, w.userID, ``); c != 409 {
				t.Fatalf("promotion after redeem => %d, want 409", c)
			}
			// clean email by C then promote: still 409 (A in writer sets)
			r6Patch(t, w, w.adminTok, w.userID, `{"email":"clean@example.com"}`)
			if c, _ := w.promote(t, w.adminTok, w.userID, ``); c != 409 {
				t.Fatalf("promotion after clean-up => %d, want 409", c)
			}
			if isAdminNow(t, w, w.userID) {
				t.Fatal("U became admin without accept")
			}
		})
	}
}

// Accept then a pre-promotion token (self-service, admin-issued, magic) must die; token issued AFTER an accepted promotion
// to a still-A inbox is the documented exception and is not asserted.
func TestR6AcceptedPromotionKillsEveryPriorToken(t *testing.T) {
	w := newReviewWorld(t)
	_, aTok := r6A(t, w)
	mail := r5Mailbox(w)
	r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox@example.com"}`)
	ss := r5Forgot(t, w, mail, "a-inbox@example.com")
	req := func(kind string) string {
		c, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/"+kind, aTok, map[string]string{})
		l, _ := asMap(t, b)["link"].(string)
		if c != 200 {
			t.Fatalf("%s => %d", kind, c)
		}
		return l[strings.Index(l, "token=")+6:]
	}
	rl := req("reset-password")
	ml := req("magic-link")
	if c, _ := w.promote(t, w.adminTok, w.userID, `,"accept_identity_set_by_other":true`); c != 200 {
		t.Fatalf("accepted promotion => %d", c)
	}
	if c := redeemReset(t, w, ss, "Aaaaaaaa-1-pw"); c == 200 {
		t.Error("self-service token survived accepted promotion")
	}
	if c := redeemReset(t, w, rl, "Aaaaaaaa-1-pw"); c == 200 {
		t.Error("admin reset token survived promotion")
	}
	if c := api(t, w, "GET", "/api/auth/magic?token="+ml, "", ""); c == 302 {
		t.Error("magic link survived promotion")
	}
	if code, _, _ := raw(t, w.srv, "POST", "/api/auth/login", "", map[string]string{"email": "a-inbox@example.com", "password": "Aaaaaaaa-1-pw"}); code == 200 {
		t.Error("login with attacker password")
	}
}

// Tokens with no recovery context (issued by a pre-Round-5 build) are refused.
func TestR6TokenWithoutContextRefusedAllKinds(t *testing.T) {
	w := newReviewWorld(t)
	mail := r5Mailbox(w)
	ss := r5Forgot(t, w, mail, "bob@example.com")
	_, rl := adminLink(t, w, "reset-password", w.userID)
	_, ml := adminLink(t, w, "magic-link", w.userID)
	db, _ := w.svc.k.SQL(context.Background())
	if _, err := db.Exec("DELETE FROM auth_recovery_context"); err != nil {
		t.Fatal(err)
	}
	if c := redeemReset(t, w, ss, "Aaaaaaaa-1-pw"); c != 401 {
		t.Errorf("ss %d", c)
	}
	if c := redeemReset(t, w, rl, "Aaaaaaaa-1-pw"); c != 401 {
		t.Errorf("rl %d", c)
	}
	if c := api(t, w, "GET", "/api/auth/magic?token="+ml, "", ""); c != 401 {
		t.Errorf("ml %d", c)
	}
}

// Refusal is not an oracle: voided/unknown/expired answers are byte-identical.
func TestR6RefusalIsNotAnOracle(t *testing.T) {
	w := newReviewWorld(t)
	_, aTok := r6A(t, w)
	mail := r5Mailbox(w)
	tk := r5Forgot(t, w, mail, "bob@example.com")
	r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox@example.com"}`) // voids tk
	body := func(tok string) (int, string) {
		c, b, _ := raw(t, w.srv, "POST", "/api/auth/password/reset", "", map[string]string{"token": tok, "password": "Aaaaaaaa-1-pw"})
		return c, string(b)
	}
	c1, b1 := body(tk)
	c2, b2 := body("deadbeef" + strings.Repeat("0", 56))
	if c1 != c2 || b1 != b2 {
		t.Errorf("oracle: voided %d %q vs unknown %d %q", c1, b1, c2, b2)
	}
	// timing, rough
	var voided, unknown time.Duration
	for i := 0; i < 3; i++ {
		tk2 := r5Forgot(t, w, mail, "a-inbox@example.com")
		r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox2`+string(rune('a'+i))+`@example.com"}`)
		mail2 := r5Mailbox(w)
		_ = mail2
		s := time.Now()
		body(tk2)
		voided += time.Since(s)
		s = time.Now()
		body("ab" + strings.Repeat("1", 62))
		unknown += time.Since(s)
		r6Patch(t, w, aTok, w.userID, `{"email":"a-inbox@example.com"}`)
	}
	t.Logf("timing voided(avg)=%v unknown(avg)=%v", voided/3, unknown/3)
}

// Admin-issued reset token survives an email change (author rationale). Prove no takeover results.
func TestR6AdminTokenSurvivesEmailChangeNoTakeover(t *testing.T) {
	w := newReviewWorld(t)
	_, aTok := r6A(t, w)
	c, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", aTok, map[string]string{})
	l, _ := asMap(t, b)["link"].(string)
	if c != 200 {
		t.Fatal(c)
	}
	tk := l[strings.Index(l, "token=")+6:]
	r6Patch(t, w, w.adminTok, w.userID, `{"email":"carol@example.com"}`)
	got := redeemReset(t, w, tk, "A-knows-this-pw-1")
	t.Logf("admin-issued token after email change by C => %d", got)
	if c, _ := w.promote(t, w.adminTok, w.userID, ``); got == 200 && c != 409 {
		t.Errorf("promotion after A's redeemed admin link => %d, want 409", c)
	}
}

// Issuer demoted: can the ex-admin still redeem the reset link it issued?
func TestR6ResetLinkIssuerDemoted(t *testing.T) {
	w := newReviewWorld(t)
	aID, aTok := r6A(t, w)
	c, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", aTok, map[string]string{})
	l, _ := asMap(t, b)["link"].(string)
	if c != 200 {
		t.Fatal(c)
	}
	tk := l[strings.Index(l, "token=")+6:]
	if err := w.svc.SetRoles(context.Background(), aID, nil); err != nil {
		t.Fatal(err)
	}
	if got := redeemReset(t, w, tk, "A-knows-this-pw-1"); got == 200 {
		t.Errorf("LOW: reset link issued by a since-demoted admin still redeems (magic links do not)")
	}
}

// Full chain: demoted issuer redeems and then authenticates as the target.
func TestR6DemotedIssuerTakesOverTarget(t *testing.T) {
	w := newReviewWorld(t)
	aID, aTok := r6A(t, w)
	c, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", aTok, map[string]string{})
	l, _ := asMap(t, b)["link"].(string)
	if c != 200 {
		t.Fatal(c)
	}
	tk := l[strings.Index(l, "token=")+6:]
	if err := w.svc.SetRoles(context.Background(), aID, nil); err != nil {
		t.Fatal(err)
	}
	if code := api(t, w, "GET", "/api/auth/admin/users", aTok, ""); code == 200 {
		t.Fatal("A still admin after demotion (D2 broken)")
	}
	redeemReset(t, w, tk, "Aaaaaaaa-1-pw")
	code, _, _ := raw(t, w.srv, "POST", "/api/auth/login", "", map[string]string{"email": "bob@example.com", "password": "Aaaaaaaa-1-pw"})
	if code == 200 {
		t.Errorf("demoted ex-admin authenticated as target via pre-demotion reset link")
	}
}
