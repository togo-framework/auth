package auth

import (
	"context"
	"strings"
	"testing"
)

// Round 5 strict ruling: provenance is security history, not last-writer state.
// Every non-holder administrator who ever set a recovery field stays a tainting
// party; a later write, a holder write or an accepted promotion never erases it.

const acceptJSON = `,"accept_identity_set_by_other":true`

func setEmailAs(t *testing.T, w *reviewWorld, tok, email string) {
	t.Helper()
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, tok, `{"email":"`+email+`"}`); c != 200 {
		t.Fatalf("set email => %d", c)
	}
}

func TestR5StrictEmailWritersAccumulate(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	setEmailAs(t, w, w.adminTok, "first@example.com")
	setEmailAs(t, w, tok2, "second@example.com")
	p := w.provenanceOf(t, w.userID)
	if !strings.Contains(p.EmailBy, w.adminID) || !strings.Contains(p.EmailBy, w.admin2ID) {
		t.Fatalf("email writers %q must hold both administrators", p.EmailBy)
	}
	// The second writer promotes: the first writer's history still taints it.
	if code, _ := w.promote(t, tok2, w.userID, ""); code != 409 {
		t.Fatalf("earlier admin's taint erased by a later write: %d", code)
	}
	if isAdminNow(t, w, w.userID) {
		t.Fatal("account promoted despite the earlier writer")
	}
}

func TestR5StrictSoleWriterStillExempt(t *testing.T) {
	w := newReviewWorld(t)
	setEmailAs(t, w, w.adminTok, "sole@example.com")
	setEmailAs(t, w, w.adminTok, "sole2@example.com")
	if code, body := w.promote(t, w.adminTok, w.userID, ""); code != 200 {
		t.Fatalf("sole writer must stay exempt: %d %v", code, body)
	}
}

func TestR5StrictHolderWriteDoesNotClear(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	setEmailAs(t, w, w.adminTok, "held@example.com")
	// The holder changes their own email: provenance must not be cleared.
	db, _ := w.svc.k.SQL(context.Background())
	_, _ = db.Exec("UPDATE users SET email = "+w.svc.ph(1)+" WHERE id = "+w.svc.ph(2), "holder@example.com", w.userID)
	if code, _ := w.promote(t, tok2, w.userID, ""); code != 409 {
		t.Fatalf("holder write cleared the taint: %d", code)
	}
}

func TestR5StrictAcceptDoesNotClear(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	setEmailAs(t, w, w.adminTok, "acc@example.com")
	if code, body := w.promote(t, tok2, w.userID, acceptJSON); code != 200 {
		t.Fatalf("explicit accept => %d %v", code, body)
	}
	p := w.provenanceOf(t, w.userID)
	if !strings.Contains(p.EmailBy, w.adminID) {
		t.Fatalf("accept erased provenance: %q", p.EmailBy)
	}
	// Demote, then try again without accept: still 409.
	if err := w.svc.SetRoles(context.Background(), w.userID, nil); err != nil {
		t.Fatalf("demote: %v", err)
	}
	if code, _ := w.promote(t, tok2, w.userID, ""); code != 409 {
		t.Fatalf("accept leaked into a later promotion: %d", code)
	}
}

func TestR5StrictPasswordWritersAccumulate(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	if c := api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, `{"password":"set-by-admin-123"}`); c != 200 {
		t.Fatalf("set-password A => %d", c)
	}
	if c := api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", tok2, `{"password":"set-by-admin2-123"}`); c != 200 {
		t.Fatalf("set-password B => %d", c)
	}
	p := w.provenanceOf(t, w.userID)
	if !strings.Contains(p.PasswordBy, w.adminID) || !strings.Contains(p.PasswordBy, w.admin2ID) {
		t.Fatalf("password writers %q must hold both administrators", p.PasswordBy)
	}
	if code, _ := w.promote(t, tok2, w.userID, ""); code != 409 {
		t.Fatalf("earlier password writer erased: %d", code)
	}
}
