package auth

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestReviewR4PromoteAndEmailChain(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	var tok string
	w.svc.k.Hooks.On(EventPasswordResetRequested, 1, func(_ context.Context, p any) error {
		if m, ok := p.(map[string]string); ok {
			tok = m["token"]
		}
		return nil
	})
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, "{\"email\":\"attacker@example.com\"}")
	api(t, w, "POST", "/api/auth/password/forgot", "", "{\"email\":\"attacker@example.com\"}")
	_ = w.svc.SetRoles(ctx, w.userID, []string{"admin"})
	if c := redeemReset(t, w, tok, "residual-password-1"); c == 200 {
		t.Logf("RESIDUAL non-blocking: self-service reset token requested before promotion works after it; email of record was set by an admin while the user was ordinary")
	}
}

func TestReviewR4CrossControlAuditCoverage(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_ADMIN_CROSS_CONTROL", "true")
	ctx := context.Background()
	b2, _ := w.svc.CreateUser(ctx, "peer@example.com", pw, []string{"admin"})
	ops := []struct{ name, m, p, body string }{
		{"impersonate", "POST", "/impersonate", "{}"}, {"reset-link", "POST", "/reset-password", "{}"},
		{"set-password", "POST", "/reset-password", "{\"password\":\"audited-pass-123\"}"}, {"magic-link", "POST", "/magic-link", "{}"},
		{"perm", "PATCH", "", "{\"permissions\":[\"x\"]}"}, {"email", "PATCH", "", "{\"email\":\"peer2@example.com\"}"},
		{"roles", "PATCH", "", "{\"roles\":[\"admin\",\"y\"]}"},
	}
	for _, o := range ops {
		before := len(w.eventsNamed(EventAdminCrossControl))
		if c := api(t, w, o.m, "/api/auth/admin/users/"+b2.ID+o.p, w.adminTok, o.body); c != 200 {
			t.Errorf("flag on: %s => %d", o.name, c)
			continue
		}
		if len(w.eventsNamed(EventAdminCrossControl)) != before+1 {
			t.Errorf("FINDING: cross-control op %s produced no %s event", o.name, EventAdminCrossControl)
		}
	}
	before := len(w.eventsNamed(EventAdminCrossControl))
	api(t, w, "DELETE", "/api/auth/admin/users/"+b2.ID, w.adminTok, "")
	if len(w.eventsNamed(EventAdminCrossControl)) == before {
		t.Errorf("delete of another admin emitted no %s event", EventAdminCrossControl)
	}
	dump := w.eventDump()
	for _, bad := range []string{"audited-pass-123", "token=", "eyJ"} {
		if strings.Contains(dump, bad) {
			t.Errorf("SECURITY secret-like value %q in events", bad)
		}
	}
	for _, body := range []string{"{\"AUTH_ADMIN_CROSS_CONTROL\":\"true\"}", "{\"cross_control\":true}"} {
		if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, body); c == 200 {
			t.Errorf("unknown field accepted: %s", body)
		}
	}
}

func TestReviewR4DefaultDeniesEveryPeerOp(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_IMPERSONATE_ADMINS", "true")
	ctx := context.Background()
	b2, _ := w.svc.CreateUser(ctx, "peer@example.com", pw, []string{"admin"})
	p := "/api/auth/admin/users/" + b2.ID
	for _, c := range []struct{ m, p, b string }{
		{"POST", p + "/impersonate", "{}"}, {"POST", p + "/reset-password", "{}"},
		{"POST", p + "/reset-password", "{\"password\":\"peer-pass-1234\"}"}, {"POST", p + "/magic-link", "{}"},
		{"PATCH", p, "{\"email\":\"z@example.com\"}"}, {"PATCH", p, "{\"roles\":[]}"}, {"PATCH", p, "{\"permissions\":[\"a\"]}"},
		{"PATCH", p, "{\"roles\":[\"admin\"],\"permissions\":[]}"},
	} {
		if code := api(t, w, c.m, c.p, w.adminTok, c.b); code != 403 {
			t.Errorf("SECURITY default config %s %s %s => %d", c.m, c.p, c.b, code)
		}
	}
	tokB := tokFor(t, w.svc, "peer@example.com")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); api(t, w, "PATCH", p, tokB, "{\"roles\":[]}") }()
	go func() { defer wg.Done(); api(t, w, "PATCH", p, w.adminTok, "{\"email\":\"q@example.com\"}") }()
	wg.Wait()
	u, _ := w.svc.userByID(ctx, b2.ID)
	if u.Email != "peer@example.com" {
		t.Errorf("SECURITY racing self-demote let another admin change the email: %s", u.Email)
	}
}

func TestReviewR4SelfPromoteStrictAndMigration(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.adminID, w.adminTok, "{\"email\":\"root2@example.com\"}"); c != 200 {
		t.Errorf("self email => %d", c)
	}
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, "{\"roles\":[\"admin\"]}"); c != 200 {
		t.Errorf("promote => %d", c)
	}
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, "{\"roles\":[],\"bogus\":1}"); c != 400 {
		t.Errorf("unknown field => %d", c)
	}
	db, _ := w.svc.k.SQL(ctx)
	if _, err := db.Exec("DROP TABLE auth_reset_issuers"); err != nil {
		t.Fatal(err)
	}
	_, _ = bootSecond(t)
	if _, err := db.Exec("SELECT count(*) FROM auth_reset_issuers"); err != nil {
		t.Errorf("table not recreated on an existing install: %v", err)
	}
}
