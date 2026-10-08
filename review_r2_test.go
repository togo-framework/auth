package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func magicSession(t *testing.T, w *reviewWorld, userID string) string {
	t.Helper()
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+userID+"/magic-link", w.adminTok, map[string]string{})
	link, _ := asMap(t, b)["link"].(string)
	if link == "" {
		t.Fatalf("no link: %s", b)
	}
	tok := link[strings.Index(link, "token=")+6:]
	req, _ := http.NewRequest("GET", w.srv.URL+"/api/auth/magic?token="+tok, nil)
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Name == SessionCookie {
			return c.Value
		}
	}
	t.Fatalf("no session cookie, status %d", res.StatusCode)
	return ""
}

// R2-2: a magic-link session is an impersonated session everywhere.
func TestReviewR2MagicSessionIsTreatedAsImpersonated(t *testing.T) {
	w := newReviewWorld(t)
	tok := magicSession(t, w, w.userID)
	if jwtClaims(t, tok)["act"] == nil {
		t.Fatalf("SECURITY magic session has no act claim")
	}
	for _, c := range []struct{ m, p string }{
		{"GET", "/api/auth/admin/users"},
		{"POST", "/api/auth/change-password"}, {"POST", "/api/auth/2fa/enroll"}, {"POST", "/api/auth/2fa/disable"},
		{"POST", "/api/auth/pin"}, {"POST", "/api/auth/tokens"},
	} {
		code, _ := rawFrom(t, w.srv, "10.9.0.1", c.m, c.p, tok, "{}")
		if code != 403 {
			t.Errorf("SECURITY magic session %s %s => %d", c.m, c.p, code)
		}
	}
	if code, _ := rawFrom(t, w.srv, "10.9.0.2", "GET", "/api/auth/me", tok, ""); code != 200 {
		t.Errorf("magic session /me => %d", code)
	}
	// issuer loses admin: session dies on the next request
	if err := w.svc.SetRoles(context.Background(), w.adminID, nil); err != nil {
		t.Fatal(err)
	}
	if code, _ := rawFrom(t, w.srv, "10.9.0.3", "GET", "/api/auth/me", tok, ""); code != 401 {
		t.Errorf("SECURITY magic session survives issuer demotion => %d", code)
	}
}

// R2-F7: every authenticating path enforces revocation, including public Verify.
func TestReviewR2VerifyEnforcesRevocation(t *testing.T) {
	w := newReviewWorld(t)
	_, tok := impersonate(t, w, w.adminTok, w.userID)
	if _, err := w.svc.Verify(tok); err != nil {
		t.Fatalf("live token rejected: %v", err)
	}
	if code, _ := rawFrom(t, w.srv, "10.9.1.1", "POST", "/api/auth/impersonation/stop", tok, "{}"); code != 200 {
		t.Fatalf("stop => %d", code)
	}
	if _, err := w.svc.Verify(tok); err == nil {
		t.Errorf("SECURITY Verify accepts a revoked impersonation token")
	}
	if _, err := w.svc.VerifyContext(context.Background(), tok); err == nil {
		t.Errorf("SECURITY VerifyContext accepts a revoked token")
	}
	for name, mk := range map[string]func() *http.Request{
		"bearer": func() *http.Request {
			r, _ := http.NewRequest("GET", w.srv.URL+"/api/auth/me", nil)
			r.Header.Set("Authorization", "Bearer "+tok)
			return r
		},
		"cookie": func() *http.Request {
			r, _ := http.NewRequest("GET", w.srv.URL+"/api/auth/me", nil)
			r.AddCookie(&http.Cookie{Name: SessionCookie, Value: tok})
			return r
		},
	} {
		res, err := http.DefaultClient.Do(mk())
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Errorf("SECURITY revoked token via %s => %d", name, res.StatusCode)
		}
	}
	// a PAT minted by a normal user must not be treated as an impersonation token
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/tokens", w.userTok, map[string]any{"name": "x", "abilities": []string{"*"}})
	pat, _ := asMap(t, b)["token"].(string)
	if pat != "" {
		if code, _ := rawFrom(t, w.srv, "10.9.1.2", "GET", "/api/auth/me", pat, ""); code != 200 {
			t.Errorf("PAT regression => %d", code)
		}
	}
}

// R2-F4: concurrent admin mutations through separate app instances.
func TestReviewR2AdminGuardSerialises(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	srv2, _ := bootSecond(t)
	base := "/api/auth/admin/users/"
	var bad, srvErr int32
	for round := 0; round < 25; round++ {
		b2, err := w.svc.CreateUser(ctx, "b"+strconv.Itoa(round)+"@example.com", pw, []string{"admin"})
		if err != nil {
			t.Fatal(err)
		}
		tokB := tokFor(t, w.svc, b2.Email)
		var wg sync.WaitGroup
		do := func(srv string, ip, m, p, tk, body string) {
			defer wg.Done()
			s := w.srv
			if srv == "2" {
				s = srv2
			}
			c, _ := rawFrom(t, s, ip, m, p, tk, body)
			if c >= 500 {
				atomic.AddInt32(&srvErr, 1)
			}
		}
		wg.Add(4)
		go do("1", "10.5.0."+strconv.Itoa(round), "PATCH", base+b2.ID, w.adminTok, "{\"roles\":[]}")
		go do("2", "10.6.0."+strconv.Itoa(round), "PATCH", base+w.adminID, tokB, "{\"roles\":[]}")
		go do("1", "10.7.0."+strconv.Itoa(round), "DELETE", base+b2.ID, w.adminTok, "")
		go do("2", "10.8.0."+strconv.Itoa(round), "DELETE", base+w.adminID, tokB, "")
		wg.Wait()
		n, _ := w.svc.countAdmins(ctx)
		if n == 0 {
			atomic.AddInt32(&bad, 1)
			break
		}
		_ = w.svc.SetRoles(ctx, w.adminID, []string{"admin"})
	}
	if bad > 0 {
		t.Errorf("SECURITY zero administrators after concurrent cross-instance mutations")
	}
	if srvErr > 0 {
		t.Errorf("FINDING regression: %d responses were 5xx under contention (lock errors surface as 500)", srvErr)
	}
}

// R2-F8: an administrator must not be able to take over another administrator
// by changing that administrator email and using the public reset flow.
func TestReviewR2AdminCannotHijackAdminViaEmailChange(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	b2, _ := w.svc.CreateUser(ctx, "victim@example.com", pw, []string{"admin"})
	var reset string
	w.svc.k.Hooks.On(EventPasswordResetRequested, 1, func(_ context.Context, p any) error {
		if m, ok := p.(map[string]string); ok {
			reset = m["token"]
		}
		return nil
	})
	code, _, _ := raw(t, w.srv, "PATCH", "/api/auth/admin/users/"+b2.ID, w.adminTok, map[string]any{"email": "attacker@example.com"})
	if code == 200 {
		rawFrom(t, w.srv, "10.9.2.1", "POST", "/api/auth/password/forgot", "", "{\"email\":\"attacker@example.com\"}")
		if reset != "" {
			c, _ := rawFrom(t, w.srv, "10.9.2.2", "POST", "/api/auth/password/reset", "", "{\"token\":\""+reset+"\",\"password\":\"hijacked-password-1\"}")
			t.Errorf("FINDING F8: admin changed another admin email (200) and reset their password via the public flow (reset => %d); refuseAdminTarget is not applied to PATCH", c)
		} else {
			t.Errorf("FINDING F8: admin changed another admin email (200); no refuseAdminTarget on PATCH")
		}
	}
}
