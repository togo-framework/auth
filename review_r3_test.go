package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func captureReset(w *reviewWorld) *string {
	var tok string
	var mu sync.Mutex
	w.svc.k.Hooks.On(EventPasswordResetRequested, 1, func(_ context.Context, p any) error {
		if m, ok := p.(map[string]string); ok {
			mu.Lock()
			tok = m["token"]
			mu.Unlock()
		}
		return nil
	})
	return &tok
}

func patchU(t *testing.T, w *reviewWorld, id, body string) int {
	t.Helper()
	c, _ := rawFrom(t, w.srv, "10.30.0."+strconv.Itoa(len(id)%200)+"", "PATCH", "/api/auth/admin/users/"+id, w.adminTok, body)
	return c
}

// F9: demote, change email, reset, promote: takes over an admin account.
func TestReviewR3DemoteThenTakeOverAdmin(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	victim, _ := w.svc.CreateUser(ctx, "victim@example.com", pw, []string{"admin"})
	reset := captureReset(w)
	steps := []string{"{\"roles\":[]}", "{\"email\":\"attacker@example.com\"}"}
	for i, b := range steps {
		c, _ := rawFrom(t, w.srv, "10.31.0."+strconv.Itoa(i), "PATCH", "/api/auth/admin/users/"+victim.ID, w.adminTok, b)
		if c != 200 {
			t.Logf("step %d refused (%d): chain blocked", i, c)
			return
		}
	}
	rawFrom(t, w.srv, "10.31.0.5", "POST", "/api/auth/password/forgot", "", "{\"email\":\"attacker@example.com\"}")
	c, _ := rawFrom(t, w.srv, "10.31.0.6", "POST", "/api/auth/password/reset", "", "{\"token\":\""+*reset+"\",\"password\":\"hijacked-password-1\"}")
	c2, _ := rawFrom(t, w.srv, "10.31.0.7", "PATCH", "/api/auth/admin/users/"+victim.ID, w.adminTok, "{\"roles\":[\"admin\"]}")
	if c == 200 && c2 == 200 {
		t.Errorf("FINDING F9: demote -> change email -> public reset -> re-promote succeeded; another administrator account is now controlled by the attacker (roles of other admins are unguarded)")
	}
}

// F10: an admin-issued reset link outlives the target becoming an administrator.
func TestReviewR3StaleResetLinkAfterPromotion(t *testing.T) {
	w := newReviewWorld(t)
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, map[string]string{})
	rl, _ := asMap(t, b)["link"].(string)
	tok := rl[strings.Index(rl, "token=")+6:]
	if err := w.svc.SetRoles(context.Background(), w.userID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	c, _ := rawFrom(t, w.srv, "10.32.0.1", "POST", "/api/auth/password/reset", "", "{\"token\":\""+tok+"\",\"password\":\"hijacked-password-2\"}")
	if c == 200 {
		t.Errorf("FINDING F10 (low/medium): reset link issued by an admin for a normal user still works after the user became an administrator")
	}
}

func TestReviewR3PatchPayloadShapes(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	victim, _ := w.svc.CreateUser(ctx, "victim@example.com", pw, []string{"admin"})
	check := func(name, body string) {
		c := patchU(t, w, victim.ID, body)
		u, _ := w.svc.userByID(ctx, victim.ID)
		if u == nil {
			t.Fatalf("%s: victim gone", name)
		}
		if strings.ToLower(u.Email) != "victim@example.com" {
			t.Errorf("SECURITY %s: victim email is now %q (status %d)", name, u.Email, c)
			_, _ = w.svc.k.SQL(ctx)
			db, _ := w.svc.k.SQL(ctx)
			_, _ = db.Exec("UPDATE users SET email = "+w.svc.ph(1)+" WHERE id = "+w.svc.ph(2), "victim@example.com", victim.ID)
		}
		if c >= 500 {
			t.Errorf("%s => %d", name, c)
		}
	}
	check("case variant", "{\"email\":\"VICTIM@example.com\"}")
	check("ws variant", "{\"email\":\"  victim@example.com  \"}")
	check("dup key last wins", "{\"email\":\"victim@example.com\",\"email\":\"attacker@example.com\"}")
	check("dup key first", "{\"email\":\"attacker@example.com\",\"email\":\"victim@example.com\"}")
	check("unknown field", "{\"Email\":\"attacker@example.com\"}")
	check("unknown id field", "{\"id\":\"x\",\"password_hash\":\"x\",\"password\":\"x\"}")
	check("null", "{\"email\":null}")
	check("array", "{\"email\":[\"attacker@example.com\"]}")
	check("roles+email", "{\"roles\":[\"admin\"],\"email\":\"attacker@example.com\"}")
	check("unicode lookalike", "{\"email\":\"attacker@example.com\u0000\"}")
	if u, _ := w.svc.userByID(ctx, victim.ID); u != nil && !isAdminUser(u) {
		t.Errorf("victim demoted by a shape that should be a no-op")
	}
}

func TestReviewR3RegisterAndCredentialRoutes(t *testing.T) {
	w := newReviewWorld(t)
	for i, e := range []string{"ROOT@example.com", " root@example.com", "Root@Example.com"} {
		c, _ := rawFrom(t, w.srv, "10.33.0."+strconv.Itoa(i), "POST", "/api/auth/register", "", "{\"email\":\""+e+"\",\"password\":\"password-xyz-123\"}")
		if c == 200 || c == 201 {
			t.Errorf("SECURITY register collision with admin email %q => %d", e, c)
		}
	}
	// the public forgot response must not reveal existence or carry the token
	c, h := rawFrom(t, w.srv, "10.33.1.1", "POST", "/api/auth/password/forgot", "", "{\"email\":\"root@example.com\"}")
	_ = h
	if c != 202 {
		t.Errorf("forgot => %d", c)
	}
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/otp", "", map[string]string{"email": "root@example.com"})
	if strings.Contains(strings.ToLower(string(b)), "code") && strings.Contains(string(b), "\"code\"") {
		t.Errorf("SECURITY OTP response carries the code: %.100s", b)
	}
}

// Racing demote and email change on one admin target: no interleaving may
// leave the victim an admin whose email the attacker changed.
func TestReviewR3RacingDemoteAndEmail(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	for round := 0; round < 10; round++ {
		v, _ := w.svc.CreateUser(ctx, "v"+strconv.Itoa(round)+"@example.com", pw, []string{"admin"})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			rawFrom(t, w.srv, "10.34.0."+strconv.Itoa(round), "PATCH", "/api/auth/admin/users/"+v.ID, w.adminTok, "{\"roles\":[]}")
		}()
		go func() {
			defer wg.Done()
			rawFrom(t, w.srv, "10.35.0."+strconv.Itoa(round), "PATCH", "/api/auth/admin/users/"+v.ID, w.adminTok, "{\"email\":\"x"+strconv.Itoa(round)+"@evil.example\"}")
		}()
		wg.Wait()
		u, _ := w.svc.userByID(ctx, v.ID)
		if u != nil && isAdminUser(u) && !strings.HasPrefix(u.Email, "v") {
			t.Errorf("SECURITY race: admin victim email changed to %q", u.Email)
		}
	}
}

// F10 (magic links): an admin-issued magic link for an ordinary user stops
// working once that user is an administrator.
func TestReviewR3StaleMagicLinkAfterPromotion(t *testing.T) {
	w := newReviewWorld(t)
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/magic-link", w.adminTok, map[string]string{})
	ml, _ := asMap(t, b)["link"].(string)
	if ml == "" {
		t.Fatalf("no link: %s", b)
	}
	if err := w.svc.SetRoles(context.Background(), w.userID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	c, _ := rawFrom(t, w.srv, "10.33.0.1", "GET", ml, "", "")
	if c != 401 {
		t.Errorf("magic link for a user promoted to admin: %d, want 401", c)
	}
}

// Admins may not change another admin's roles or permissions by default, but
// may promote a non-admin and demote themselves (last-admin rule applies).
func TestAdminRolePolicyAmongAdmins(t *testing.T) {
	w := newAdminWorld(t)
	two, _ := w.svc.CreateUser(context.Background(), "two@example.com", pw, []string{"admin"})
	patch := func(id string, body map[string]any) int {
		c, _, _ := raw(t, w.srv, http.MethodPatch, "/api/auth/admin/users/"+id, w.adminTok, body)
		return c
	}
	for _, body := range []map[string]any{{"roles": []string{}}, {"permissions": []string{"x"}}, {"email": "x@example.com"}} {
		if c := patch(two.ID, body); c != http.StatusForbidden {
			t.Errorf("%v on another admin: %d", body, c)
		}
	}
	if c := patch(w.userID, map[string]any{"roles": []string{"admin"}}); c != http.StatusOK {
		t.Errorf("promoting a non-admin: %d", c)
	}
	t.Setenv("AUTH_ADMIN_CROSS_CONTROL", "true")
	if c := patch(two.ID, map[string]any{"roles": []string{}}); c != http.StatusOK {
		t.Errorf("opt-in should relax the restriction: %d", c)
	}
}

// Under the exception every cross-admin operation is audited.
func TestAdminCrossControlIsAudited(t *testing.T) {
	w := newAdminWorld(t)
	two, _ := w.svc.CreateUser(context.Background(), "two@example.com", pw, []string{"admin"})
	got := w.capture(EventAdminCrossControl)
	t.Setenv("AUTH_ADMIN_CROSS_CONTROL", "true")
	base := "/api/auth/admin/users/" + two.ID
	if c, _, _ := raw(t, w.srv, http.MethodPatch, base, w.adminTok, map[string]any{"roles": []string{}}); c != http.StatusOK {
		t.Fatalf("patch: %d", c)
	}
	if c, _, _ := raw(t, w.srv, http.MethodPost, base+"/magic-link", w.adminTok, map[string]string{}); c != http.StatusOK {
		t.Fatalf("magic: %d", c)
	}
	// Ordinary target: no cross-control event.
	raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+w.userID+"/magic-link", w.adminTok, map[string]string{})
	if len(*got) != 1 {
		t.Fatalf("events: %v", *got)
	}
	e := (*got)[0].(map[string]string)
	if e["actor_id"] != w.adminID || e["target_id"] != two.ID || e["operation"] != "update:roles" || e["policy"] != "AUTH_ADMIN_CROSS_CONTROL" {
		t.Fatalf("event: %v", e)
	}
}
