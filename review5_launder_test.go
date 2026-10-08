package auth

import (
	"context"
	"testing"
)

// r5Mailbox captures self-service reset tokens (the "A controls the inbox" model).
func r5Mailbox(w *reviewWorld) func() string {
	var last string
	w.svc.k.Hooks.On(EventPasswordResetRequested, 1, func(_ context.Context, p any) error {
		if m, ok := p.(map[string]string); ok {
			last = m["token"]
		}
		return nil
	})
	return func() string { return last }
}

// F-R5-1a: A (admin) points normal U's email at an inbox A controls and uses
// the PUBLIC reset flow to set a password A knows. Admin C then cleans the
// email and promotes U in ONE PATCH (own-write exemption). Expectation per
// I1/I4: C must not be able to hand A the admin account silently (409), or A's
// credential must be dead. Observed: see assertions.
func TestReview5LaunderViaPromoterEmailWrite(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	a, _ := w.svc.CreateUser(ctx, "evil-a@example.com", pw, []string{"admin"})
	_ = a
	aTok := tokFor(t, w.svc, "evil-a@example.com")
	mail := r5Mailbox(w)

	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, aTok, `{"email":"a-inbox@example.com"}`); c != 200 {
		t.Fatalf("A email change => %d", c)
	}
	if c := api(t, w, "POST", "/api/auth/password/forgot", "", `{"email":"a-inbox@example.com"}`); c != 202 {
		t.Fatalf("forgot => %d", c)
	}
	tk := mail()
	if tk == "" {
		t.Fatal("no token captured")
	}
	if c := redeemReset(t, w, tk, "A-knows-this-pw-1"); c != 200 {
		t.Fatalf("redeem => %d", c)
	}
	// C cleans the email and promotes in one request.
	c, body := w.promote(t, w.adminTok, w.userID, `,"email":"bob-clean@example.com"`)
	t.Logf("C promote+email-change => %d %v", c, body)
	if c != 200 {
		t.Skipf("blocked with %d (gate held)", c)
	}
	// A now logs in with the password it chose.
	code, b, _ := raw(t, w.srv, "POST", "/api/auth/login", "", map[string]string{"email": "bob-clean@example.com", "password": "A-knows-this-pw-1"})
	if code == 200 {
		utok, _ := asMap(t, b)["token"].(string)
		if api(t, w, "GET", "/api/auth/admin/users", utok, "") == 200 {
			t.Errorf("SECURITY F-R5-1a: A knows the password of the account C promoted (email of record is C's); A is admin U (I1/I4/X1/X9 violated)")
		}
	}
}

// F-R5-1b: same, but C promotes WITHOUT touching the email (must 409), then
// accepts. Control: proves the gate does fire for the email taint.
func TestReview5ControlEmailTaintGate(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, _ = w.svc.CreateUser(ctx, "evil-a@example.com", pw, []string{"admin"})
	aTok := tokFor(t, w.svc, "evil-a@example.com")
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, aTok, `{"email":"a-inbox@example.com"}`)
	if c, _ := w.promote(t, w.adminTok, w.userID, ``); c != 409 {
		t.Errorf("control: promote of A-tainted email => %d want 409", c)
	}
}

// F-R5-1c: a self-service token issued to A's inbox BEFORE promotion survives
// both the email change and the promotion, and redeems unconditionally.
func TestReview5SelfServiceTokenSurvivesPromotion(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, _ = w.svc.CreateUser(ctx, "evil-a@example.com", pw, []string{"admin"})
	aTok := tokFor(t, w.svc, "evil-a@example.com")
	mail := r5Mailbox(w)
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, aTok, `{"email":"a-inbox@example.com"}`)
	api(t, w, "POST", "/api/auth/password/forgot", "", `{"email":"a-inbox@example.com"}`)
	tk := mail()
	if tk == "" {
		t.Fatal("no token")
	}
	c, _ := w.promote(t, w.adminTok, w.userID, `,"email":"bob-clean@example.com"`)
	if c != 200 {
		// try the accepted path: C knowingly accepts after seeing 409
		c, _ = w.promote(t, w.adminTok, w.userID, `,"accept_identity_set_by_other":true`)
	}
	t.Logf("promotion => %d", c)
	if c == 200 {
		if rc := redeemReset(t, w, tk, "A-knows-this-pw-2"); rc == 200 {
			t.Errorf("SECURITY F-R5-1c: self-service token issued to the pre-promotion email still resets the password of the now-admin account")
		}
	}
}

// F-R5-1d: the email write and the promotion are SEPARATE requests. C's plain
// email edit (a normal, allowed operation on a non-admin) overwrites the sticky
// email provenance, so the later promotion carries no taint at all.
func TestReview5LaunderViaSeparateEmailEdit(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, _ = w.svc.CreateUser(ctx, "evil-a@example.com", pw, []string{"admin"})
	aTok := tokFor(t, w.svc, "evil-a@example.com")
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, aTok, `{"email":"a-inbox@example.com"}`)
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"email":"bob-clean@example.com"}`); c != 200 {
		t.Fatalf("C email edit => %d", c)
	}
	// A previously set the PASSWORD through set-password: that taint must survive.
	if c, _ := w.promote(t, w.adminTok, w.userID, ``); c != 200 {
		t.Skipf("promotion refused %d", c)
	}
	t.Errorf("SECURITY F-R5-1d: A-set email taint was erased by C's unrelated email edit; promotion returned 200 with no confirmation")
}
