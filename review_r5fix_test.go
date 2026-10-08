package auth

import (
	"context"
	"strings"
	"testing"
)

// Round 5 correction (auth#6, threat model v2 "Round 5 amendment"): F-R5-1 and
// F-R5-1c. These sit beside the reviewer's review5_launder_test.go, which is
// kept unchanged.
//
//	(a) promotion judges the provenance stored BEFORE the request
//	(b) a credential set through a recovery channel inherits the channel's provenance
//	(c) recovery tokens do not survive an email change or a change of admin status

// r5Setup returns a world with admin A (evil-a) who pointed U's email at an
// inbox A controls. w.adminTok (root) plays admin C.
func r5Setup(t *testing.T) (w *reviewWorld, aID string, mail func() string) {
	t.Helper()
	w = newReviewWorld(t)
	a, err := w.svc.CreateUser(context.Background(), "evil-a@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	aTok := tokFor(t, w.svc, "evil-a@example.com")
	mail = r5Mailbox(w)
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, aTok, `{"email":"a-inbox@example.com"}`); c != 200 {
		t.Fatalf("A email change => %d", c)
	}
	return w, a.ID, mail
}

func r5Forgot(t *testing.T, w *reviewWorld, mail func() string, email string) string {
	t.Helper()
	if c := api(t, w, "POST", "/api/auth/password/forgot", "", `{"email":"`+email+`"}`); c != 202 {
		t.Fatalf("forgot => %d", c)
	}
	tk := mail()
	if tk == "" {
		t.Fatal("no token captured")
	}
	return tk
}

// 1. The exact Round 5 chain: the promotion that also changes the email is
// refused, and A ends with no way in.
func TestR5LaunderChainRefusedAndAHasNoAccess(t *testing.T) {
	w, aID, mail := r5Setup(t)
	tk := r5Forgot(t, w, mail, "a-inbox@example.com")
	if c := redeemReset(t, w, tk, "A-knows-this-pw-1"); c != 200 {
		t.Fatalf("redeem => %d", c)
	}
	if p := w.provenanceOf(t, w.userID); p.PasswordBy != aID {
		t.Fatalf("self-service redeem through A's inbox must record password provenance A, got %q", p.PasswordBy)
	}
	code, body := w.promote(t, w.adminTok, w.userID, `,"email":"bob-clean@example.com"`)
	if code != 409 || body["error"] != "identity_set_by_other_admin" {
		t.Fatalf("promote+email change => %d %v, want 409", code, body)
	}
	tf, _ := body["tainted_fields"].([]any)
	if len(tf) != 2 {
		t.Errorf("tainted_fields = %v, want email and password", tf)
	}
	if isAdminNow(t, w, w.userID) {
		t.Fatal("409 must not promote")
	}
	u, _ := w.svc.userByID(context.Background(), w.userID)
	if u.Email != "a-inbox@example.com" {
		t.Errorf("a refused promotion must not apply its email change, got %q", u.Email)
	}
}

// 2. Same flow without the email change in the request: 409.
func TestR5SameFlowWithoutEmailChange409(t *testing.T) {
	w, _, mail := r5Setup(t)
	tk := r5Forgot(t, w, mail, "a-inbox@example.com")
	if c := redeemReset(t, w, tk, "A-knows-this-pw-1"); c != 200 {
		t.Fatalf("redeem => %d", c)
	}
	if code, _ := w.promote(t, w.adminTok, w.userID, ""); code != 409 {
		t.Fatalf("promote => %d, want 409", code)
	}
}

// Laundering through the email field is closed even with no password involved,
// and an explicit accept is the only way through (and is audited).
func TestR5EmailFieldInPromotionDoesNotLaunder(t *testing.T) {
	w, _, _ := r5Setup(t)
	if code, _ := w.promote(t, w.adminTok, w.userID, `,"email":"bob-clean@example.com"`); code != 409 {
		t.Fatalf("promote+email change over A-set email => %d, want 409", code)
	}
	if code, _ := w.promote(t, w.adminTok, w.userID, `,"email":"bob-clean@example.com","`+acceptField+`":true`); code != 200 {
		t.Fatalf("explicit accept => %d", code)
	}
	if ev := w.eventsNamed(EventAdminPromoted); len(ev) != 1 || !strings.Contains(ev[0], "true") {
		t.Errorf("accept not audited: %v", ev)
	}
}

// 3. A reset token issued before an email change is refused afterwards, burned,
// and the refusal looks like any other invalid token.
func TestR5TokenBeforeEmailChangeRefused(t *testing.T) {
	w := newReviewWorld(t)
	mail := r5Mailbox(w)
	tk := r5Forgot(t, w, mail, "bob@example.com")
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"email":"bob-new@example.com"}`); c != 200 {
		t.Fatalf("email change => %d", c)
	}
	refused, rbody, _ := raw(t, w.srv, "POST", "/api/auth/password/reset", "", map[string]string{"token": tk, "password": "attacker-pw-1234"})
	garbage, gbody, _ := raw(t, w.srv, "POST", "/api/auth/password/reset", "", map[string]string{"token": "nope-not-a-token", "password": "attacker-pw-1234"})
	if refused != 401 || garbage != 401 || string(rbody) != string(gbody) {
		t.Fatalf("refusal must equal an unknown token: %d %q vs %d %q", refused, rbody, garbage, gbody)
	}
	if loginCode(t, w, "bob-new@example.com", "attacker-pw-1234") == 200 {
		t.Fatal("refused token changed the password")
	}
	if loginCode(t, w, "bob-new@example.com", pw) != 200 {
		t.Fatal("password changed by a refused token")
	}
	// Burned: still refused, and a fresh token for the new address works.
	if c := redeemReset(t, w, tk, "attacker-pw-5678"); c != 401 {
		t.Fatalf("burned token => %d", c)
	}
	tk2 := r5Forgot(t, w, mail, "bob-new@example.com")
	if c := redeemReset(t, w, tk2, "holder-new-pw-123"); c != 200 {
		t.Fatalf("fresh token after the change => %d", c)
	}
}

// 4. A reset token issued before a promotion is refused after it (untainted
// promotion through the API, and through the trusted SetRoles API).
func TestR5TokenBeforePromotionRefused(t *testing.T) {
	for name, promote := range map[string]func(t *testing.T, w *reviewWorld){
		"api": func(t *testing.T, w *reviewWorld) {
			if c, b := w.promote(t, w.adminTok, w.userID, ""); c != 200 {
				t.Fatalf("promote => %d %v", c, b)
			}
		},
		"SetRoles": func(t *testing.T, w *reviewWorld) {
			if err := w.svc.SetRoles(context.Background(), w.userID, []string{"admin"}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		promote := promote
		t.Run(name, func(t *testing.T) {
			w := newReviewWorld(t)
			mail := r5Mailbox(w)
			tk := r5Forgot(t, w, mail, "bob@example.com")
			promote(t, w)
			if c := redeemReset(t, w, tk, "post-promotion-pw-1"); c != 401 {
				t.Fatalf("pre-promotion token redeemed on the admin account => %d", c)
			}
			if loginCode(t, w, "bob@example.com", pw) != 200 {
				t.Fatal("password changed by a refused token")
			}
		})
	}
}

// The same after an accepted promotion over A's inbox (the reviewer's 1c).
func TestR5TokenBeforeAcceptedPromotionRefused(t *testing.T) {
	w, _, mail := r5Setup(t)
	tk := r5Forgot(t, w, mail, "a-inbox@example.com")
	if c, b := w.promote(t, w.adminTok, w.userID, `,"`+acceptField+`":true`); c != 200 {
		t.Fatalf("accepted promotion => %d %v", c, b)
	}
	if c := redeemReset(t, w, tk, "A-knows-this-pw-2"); c != 401 {
		t.Fatalf("token survived the promotion => %d", c)
	}
}

// A promote-then-demote round trip leaves the status as it was but still voids
// the token (privilege epoch), for self-service and admin-issued tokens, and for
// magic links.
func TestR5PromoteDemoteRoundTripVoidsTokens(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	mail := r5Mailbox(w)
	self := r5Forgot(t, w, mail, "bob@example.com")
	_, issued := adminLink(t, w, "reset-password", w.userID)
	_, magic := adminLink(t, w, "magic-link", w.userID)
	if err := w.svc.SetRoles(ctx, w.userID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	if err := w.svc.SetRoles(ctx, w.userID, nil); err != nil {
		t.Fatal(err)
	}
	if c := redeemReset(t, w, self, "round-trip-pw-12"); c != 401 {
		t.Errorf("self-service token after round trip => %d", c)
	}
	if c := redeemReset(t, w, issued, "round-trip-pw-34"); c != 401 {
		t.Errorf("admin-issued token after round trip => %d", c)
	}
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/magic?token="+magic, "", nil); code != 401 {
		t.Errorf("magic link after round trip => %d", code)
	}
	if loginCode(t, w, "bob@example.com", pw) != 200 {
		t.Error("password changed by a refused token")
	}
}

// Magic links still work when nothing relevant changed.
func TestR5MagicLinkStillRedeems(t *testing.T) {
	w := newReviewWorld(t)
	_, magic := adminLink(t, w, "magic-link", w.userID)
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/magic?token="+magic, "", nil); code != 302 {
		t.Fatalf("magic link => %d, want 302", code)
	}
}

// 5. Provenance follows the recovery channel: a password set through an inbox
// whose email an admin set is that admin's, and survives later holder changes.
func TestR5ProvenanceSurvivesSelfServiceRedemption(t *testing.T) {
	w, aID, mail := r5Setup(t)
	tk := r5Forgot(t, w, mail, "a-inbox@example.com")
	if c := redeemReset(t, w, tk, "A-knows-this-pw-1"); c != 200 {
		t.Fatalf("redeem => %d", c)
	}
	p := w.provenanceOf(t, w.userID)
	if p.EmailBy != aID || p.PasswordBy != aID {
		t.Fatalf("provenance = %+v, want email and password by A", p)
	}
	// A later change of the password does not clear it.
	if err := w.svc.SetPassword(context.Background(), w.userID, "holder-chosen-456"); err != nil {
		t.Fatal(err)
	}
	if code, _ := w.promote(t, w.adminTok, w.userID, ""); code != 409 {
		t.Fatalf("promote => %d, want 409", code)
	}
}

// 7. Normal self-service recovery records nothing and works; the admin-issued
// link still records its issuer.
func TestR5ProvenanceByChannel(t *testing.T) {
	w := newReviewWorld(t)
	mail := r5Mailbox(w)
	tk := r5Forgot(t, w, mail, "bob@example.com")
	if c := redeemReset(t, w, tk, "holder-chosen-pw-1"); c != 200 {
		t.Fatalf("redeem => %d", c)
	}
	if loginCode(t, w, "bob@example.com", "holder-chosen-pw-1") != 200 {
		t.Fatal("holder cannot sign in with the recovered password")
	}
	if p := w.provenanceOf(t, w.userID); p != (provenance{}) {
		t.Errorf("normal self-service recovery recorded provenance %+v", p)
	}
	_, rt := adminLink(t, w, "reset-password", w.userID)
	if c := redeemReset(t, w, rt, "link-password-12"); c != 200 {
		t.Fatalf("link redeem => %d", c)
	}
	if p := w.provenanceOf(t, w.userID); p.PasswordBy != w.adminID {
		t.Errorf("admin link provenance = %q", p.PasswordBy)
	}
}

// An administrator recovering their own account through their own inbox keeps
// working.
func TestR5AdminSelfServiceRecoveryWorks(t *testing.T) {
	w := newReviewWorld(t)
	mail := r5Mailbox(w)
	tk := r5Forgot(t, w, mail, "root@example.com")
	if c := redeemReset(t, w, tk, "admin-recovered-pw-1"); c != 200 {
		t.Fatalf("admin self-service redeem => %d", c)
	}
}

// 6. The accept is audited, scoped to its request, and does not launder: after
// a later demotion the taint is still there and a second promotion needs a new
// accept.
func TestR5AcceptAuditedScopedAndTaintVisible(t *testing.T) {
	w, aID, _ := r5Setup(t)
	if c, _ := w.promote(t, w.adminTok, w.userID, ""); c != 409 {
		t.Fatalf("no accept => %d", c)
	}
	if c, b := w.promote(t, w.adminTok, w.userID, `,"`+acceptField+`":true`); c != 200 {
		t.Fatalf("accept => %d %v", c, b)
	}
	ev := w.eventsNamed(EventAdminPromoted)
	if len(ev) != 1 || !strings.Contains(ev[0], "true") || !strings.Contains(ev[0], "email") {
		t.Fatalf("accept not audited with the tainted field: %v", ev)
	}
	if p := w.provenanceOf(t, w.userID); p.EmailBy != aID {
		t.Errorf("accept cleared the taint: %+v", p)
	}
	if err := w.svc.SetRoles(context.Background(), w.userID, nil); err != nil {
		t.Fatal(err)
	}
	if c, _ := w.promote(t, w.adminTok, w.userID, ""); c != 409 {
		t.Fatalf("second promotion without a new accept => %d, want 409", c)
	}
}

// Upgrade: a token that has no recovery context (issued before the table
// existed) is refused and answers like any invalid token.
func TestR5TokenWithoutContextRefused(t *testing.T) {
	w := newReviewWorld(t)
	mail := r5Mailbox(w)
	tk := r5Forgot(t, w, mail, "bob@example.com")
	db, _ := w.svc.k.SQL(context.Background())
	if _, err := db.Exec("DELETE FROM auth_recovery_context"); err != nil {
		t.Fatal(err)
	}
	if c := redeemReset(t, w, tk, "no-context-pw-123"); c != 401 {
		t.Fatalf("context-less token => %d", c)
	}
}

// Deleting an account removes its recovery context and epoch.
func TestR5DeleteScrubsRecoveryState(t *testing.T) {
	w := newReviewWorld(t)
	mail := r5Mailbox(w)
	r5Forgot(t, w, mail, "bob@example.com")
	_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
	_ = w.svc.SetRoles(context.Background(), w.userID, nil)
	if c := api(t, w, "DELETE", "/api/auth/admin/users/"+w.userID, w.adminTok, ""); c != 200 {
		t.Fatalf("delete => %d", c)
	}
	db, _ := w.svc.k.SQL(context.Background())
	for _, tbl := range []string{"auth_recovery_context", "auth_priv_epoch"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM "+tbl+" WHERE user_id = "+w.svc.ph(1), w.userID).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s rows after delete = %d (%v)", tbl, n, err)
		}
	}
}
