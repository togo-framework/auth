package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func impersonate(t *testing.T, w *reviewWorld, actorTok, targetID string) (int, string) {
	t.Helper()
	code, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+targetID+"/impersonate", actorTok, map[string]string{})
	if code != 200 {
		return code, ""
	}
	tok, _ := asMap(t, b)["token"].(string)
	return code, tok
}

// (4) a normal user, a PAT and an impersonation token can not impersonate.
func TestReviewOnlyARealAdminSessionCanImpersonate(t *testing.T) {
	w := newReviewWorld(t)
	other, _ := w.svc.CreateUser(context.Background(), "carol@example.com", pw, nil)
	if code, _ := impersonate(t, w, w.userTok, other.ID); code != 403 {
		t.Errorf("SECURITY normal user impersonate: %d", code)
	}
	if code, _ := impersonate(t, w, "", other.ID); code != 401 {
		t.Errorf("anonymous impersonate: %d", code)
	}
	code, tok := impersonate(t, w, w.adminTok, w.userID)
	if code != 200 {
		t.Fatalf("admin impersonate: %d", code)
	}
	if code, _ := impersonate(t, w, tok, other.ID); code != 403 {
		t.Errorf("SECURITY chained impersonation: %d", code)
	}
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/tokens", w.adminTok, map[string]any{"name": "x", "abilities": []string{"*"}})
	pat, _ := asMap(t, b)["token"].(string)
	if code, _ := impersonate(t, w, pat, other.ID); code != 403 {
		t.Errorf("SECURITY PAT impersonate: %d", code)
	}
	// forged act claim on a non-admin token signed with the server key:
	// requireAdmin must still refuse it.
	c := claimsFor(w.userID, "")
	c["act"] = map[string]string{"sub": w.adminID}
	c["jti"] = "forged"
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/admin/users", signWith(t, w.svc.secret, jwt.SigningMethodHS256, c), nil); code != 403 && code != 401 {
		t.Errorf("SECURITY forged act reached admin API: %d", code)
	}
}

// (5) admin to admin impersonation: default deny, exact opt-in semantics.
func TestReviewAdminToAdminImpersonation(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	second, _ := w.svc.CreateUser(ctx, "second@example.com", pw, []string{"editor", "admin"})
	for _, v := range []string{"", "false", "1", "yes", "on", "truee", " true", "TRUE "} {
		t.Setenv("AUTH_IMPERSONATE_ADMINS", v)
		code, _ := impersonate(t, w, w.adminTok, second.ID)
		want := 403
		if strings.EqualFold(v, "true") {
			want = 200
		}
		if code != want {
			t.Errorf("AUTH_IMPERSONATE_ADMINS=%q: got %d want %d", v, code, want)
		}
	}
	for _, roles := range [][]string{{"admin"}, {"a", "admin", "z"}, {" admin "}, {"admin", "admin"}} {
		if err := w.svc.SetRoles(ctx, second.ID, roles); err != nil {
			t.Fatal(err)
		}
		t.Setenv("AUTH_IMPERSONATE_ADMINS", "")
		if code, _ := impersonate(t, w, w.adminTok, second.ID); code == 200 {
			t.Errorf("SECURITY admin impersonated with roles %v", roles)
		}
	}
	t.Setenv("AUTH_IMPERSONATE_ADMINS", "true")
	if err := w.svc.SetRoles(ctx, second.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	code, tok := impersonate(t, w, w.adminTok, second.ID)
	if code != 200 {
		t.Fatalf("opt-in impersonate: %d", code)
	}
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/admin/users", tok, nil); code != 403 {
		t.Errorf("SECURITY impersonated admin reached admin API: %d", code)
	}
	if code, _ := impersonate(t, w, tok, w.adminID); code != 403 {
		t.Errorf("SECURITY impersonated admin chained impersonation: %d", code)
	}
}

// FINDING F1: the admin to admin deny is bypassable through the other
// credential-minting routes. With default config an administrator can take over
// another administrator with a magic link or by setting the password, and the
// resulting session carries no act claim.
func TestReviewAdminCanNotTakeOverAnotherAdminByOtherMeans(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_IMPERSONATE_ADMINS", "")
	second, _ := w.svc.CreateUser(context.Background(), "second@example.com", pw, []string{"admin"})
	code, _, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+second.ID+"/magic-link", w.adminTok, map[string]string{})
	if code == 200 {
		t.Errorf("FINDING F1a: magic link issued for another administrator: %d", code)
	}
	code, _, _ = raw(t, w.srv, "POST", "/api/auth/admin/users/"+second.ID+"/reset-password", w.adminTok, map[string]string{"password": "attacker-chosen-password"})
	if code == 200 {
		t.Errorf("FINDING F1b: administrator set another administrator password: %d", code)
	}
}

// FINDING F2: redeeming a magic link must be attributable (an audit event naming
// the link issuer), otherwise it is an impersonation with no trail.
func TestReviewMagicLinkRedemptionIsAudited(t *testing.T) {
	w := newReviewWorld(t)
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/magic-link", w.adminTok, map[string]string{})
	link, _ := asMap(t, b)["link"].(string)
	before := w.eventDump()
	code, _, _ := raw(t, w.srv, "GET", link, "", nil)
	if code != 302 {
		t.Fatalf("redeem: %d", code)
	}
	after := w.eventDump()
	if !strings.Contains(after[len(before):], w.adminID) {
		t.Errorf("FINDING F2: no event on redemption names the issuing admin; new events: %q", after[len(before):])
	}
}

// (7) act.sub survives, can not be stripped or forged; no escalation.
func TestReviewImpersonatedSessionCannotEscalate(t *testing.T) {
	w := newReviewWorld(t)
	code, tok := impersonate(t, w, w.adminTok, w.userID)
	if code != 200 {
		t.Fatalf("impersonate: %d", code)
	}
	if cl := jwtClaims(t, tok); cl["act"] == nil || cl["jti"] == nil || cl["sub"] != w.userID {
		t.Fatalf("claims: %v", cl)
	}
	parts := strings.Split(tok, ".")
	forged := []string{
		parts[0] + "." + parts[1] + ".AAAA",
		signWith(t, []byte("another-secret-another-secret-another"), jwt.SigningMethodHS256, claimsFor(w.userID, "")),
		parts[0] + "." + parts[1],
	}
	for _, f := range forged {
		if code, _, _ := raw(t, w.srv, "GET", "/api/auth/me", f, nil); code != 401 {
			t.Errorf("SECURITY forged token accepted by /me: %d", code)
		}
	}
	_, b, _ := raw(t, w.srv, "GET", "/api/auth/me", tok, nil)
	if asMap(t, b)["impersonator"] != w.adminID {
		t.Errorf("impersonator not reported: %s", b)
	}
	type rq struct {
		m, p string
		body any
	}
	blocked := []rq{
		{"GET", "/api/auth/admin/users", nil},
		{"POST", "/api/auth/admin/users/" + w.userID + "/impersonate", map[string]string{}},
		{"POST", "/api/auth/admin/users/" + w.adminID + "/magic-link", map[string]string{}},
		{"POST", "/api/auth/change-password", map[string]string{"old_password": pw, "new_password": "brand-new-password-1"}},
		{"POST", "/api/auth/2fa/enroll", map[string]string{}},
		{"POST", "/api/auth/2fa/verify", map[string]string{"code": "000000"}},
		{"POST", "/api/auth/2fa/disable", map[string]string{"code": "000000"}},
		{"POST", "/api/auth/pin", map[string]string{"pin": "1234"}},
		{"POST", "/api/auth/tokens", map[string]any{"name": "persist", "abilities": []string{"*"}}},
	}
	for _, r := range blocked {
		if code, b, _ := raw(t, w.srv, r.m, r.p, tok, r.body); code != 403 {
			t.Errorf("SECURITY impersonated session %s %s => %d %s", r.m, r.p, code, b)
		}
	}
	if _, err := w.svc.Guard("").Auth.Attempt(context.Background(), "bob@example.com", pw); err != nil {
		t.Errorf("SECURITY borrowed password changed: %v", err)
	}
	req, _ := http.NewRequest("GET", w.srv.URL+"/api/auth/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Errorf("SECURITY impersonation cookie reached admin API: %d", res.StatusCode)
	}
}

// Stop revokes; the revoked jti is refused on every authenticated route.
func TestReviewStopRevokesEverywhere(t *testing.T) {
	w := newReviewWorld(t)
	_, tok := impersonate(t, w, w.adminTok, w.userID)
	if code, _, _ := raw(t, w.srv, "POST", "/api/auth/impersonation/stop", w.userTok, map[string]string{}); code != 400 {
		t.Errorf("stop with a normal token should be 400, got %d", code)
	}
	if code, _, _ := raw(t, w.srv, "POST", "/api/auth/impersonation/stop", "", map[string]string{}); code != 401 {
		t.Errorf("stop anonymous: %d", code)
	}
	if code, _, _ := raw(t, w.srv, "POST", "/api/auth/impersonation/stop", tok, map[string]string{}); code != 200 {
		t.Fatalf("stop: %d", code)
	}
	type rq struct{ m, p string }
	for _, r := range []rq{
		{"GET", "/api/auth/me"}, {"GET", "/api/auth/tokens"}, {"POST", "/api/auth/logout"},
		{"POST", "/api/auth/pin/verify"}, {"GET", "/api/auth/admin/users"},
		{"POST", "/api/auth/impersonation/stop"}, {"DELETE", "/api/auth/tokens/x"},
	} {
		if code, _, _ := raw(t, w.srv, r.m, r.p, tok, map[string]string{}); code != 401 {
			t.Errorf("SECURITY revoked token on %s %s => %d", r.m, r.p, code)
		}
	}
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/me", w.adminTok, nil); code != 200 {
		t.Errorf("admin session broken by stop: %d", code)
	}
	if len(w.eventsNamed(EventImpersonationEnded)) != 1 || len(w.eventsNamed(EventUserImpersonated)) != 1 {
		t.Errorf("audit events: %s", w.eventDump())
	}
	_, tok2 := impersonate(t, w, w.adminTok, w.userID)
	var wg sync.WaitGroup
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, _ := raw(t, w.srv, "POST", "/api/auth/impersonation/stop", tok2, map[string]string{})
			codes <- c
		}()
	}
	wg.Wait()
	close(codes)
	for c := range codes {
		if c == 500 {
			t.Errorf("concurrent stop returned 500")
		}
	}
}

// Dies when the actor is deleted or the target is deleted.
func TestReviewImpersonationDiesWithActorOrTarget(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	second, _ := w.svc.CreateUser(ctx, "second@example.com", pw, []string{"admin"})
	secondTok := tokFor(t, w.svc, "second@example.com")
	_, tok := impersonate(t, w, secondTok, w.userID)
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/me", tok, nil); code != 200 {
		t.Fatalf("precondition %d", code)
	}
	if code, _, _ := raw(t, w.srv, "DELETE", "/api/auth/admin/users/"+second.ID, w.adminTok, nil); code != 200 {
		t.Fatalf("delete actor: %d", code)
	}
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/me", tok, nil); code != 401 {
		t.Errorf("SECURITY token of a deleted actor still works: %d", code)
	}
	_, tok = impersonate(t, w, w.adminTok, w.userID)
	raw(t, w.srv, "DELETE", "/api/auth/admin/users/"+w.userID, w.adminTok, nil)
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/me", tok, nil); code != 401 {
		t.Errorf("SECURITY token of a deleted target still works: %d", code)
	}
}
