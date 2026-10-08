package auth

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var ipSeq int
var ipMu sync.Mutex

func nip() string {
	ipMu.Lock()
	defer ipMu.Unlock()
	ipSeq++
	return "10.50." + strconv.Itoa(ipSeq/250) + "." + strconv.Itoa(ipSeq%250+1)
}

func api(t *testing.T, w *reviewWorld, m, p, tok, body string) int {
	t.Helper()
	c, _ := rawFrom(t, w.srv, nip(), m, p, tok, body)
	return c
}

func adminLink(t *testing.T, w *reviewWorld, kind, id string) (int, string) {
	t.Helper()
	c, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+id+"/"+kind, w.adminTok, map[string]string{})
	l, _ := asMap(t, b)["link"].(string)
	if i := strings.Index(l, "token="); i >= 0 {
		return c, l[i+6:]
	}
	return c, ""
}

func redeemReset(t *testing.T, w *reviewWorld, tok, pass string) int {
	return api(t, w, "POST", "/api/auth/password/reset", "", "{\"token\":\""+tok+"\",\"password\":\""+pass+"\"}")
}

func loginCode(t *testing.T, w *reviewWorld, email, pass string) int {
	return api(t, w, "POST", "/api/auth/login", "", "{\"email\":\""+email+"\",\"password\":\""+pass+"\"}")
}

func TestReviewR4IssueThenPromoteThenRedeem(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, rt := adminLink(t, w, "reset-password", w.userID)
	_, mt := adminLink(t, w, "magic-link", w.userID)
	_ = w.svc.SetRoles(ctx, w.userID, []string{"admin"})
	if c := redeemReset(t, w, rt, "hijacked-pass-1"); c == 200 {
		t.Errorf("SECURITY T1 reset redeemed after promotion")
	}
	if c := api(t, w, "GET", "/api/auth/magic?token="+mt, "", ""); c == 200 || c == 302 {
		t.Errorf("SECURITY T2 magic redeemed after promotion: %d", c)
	}
	if loginCode(t, w, "bob@example.com", "hijacked-pass-1") == 200 {
		t.Errorf("SECURITY password changed")
	}
}

func TestReviewR4IssuerLosesAdmin(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, _ = w.svc.CreateUser(ctx, "second@example.com", pw, []string{"admin"})
	_, mt := adminLink(t, w, "magic-link", w.userID)
	_, mt2 := adminLink(t, w, "magic-link", w.userID)
	_ = w.svc.SetRoles(ctx, w.adminID, nil)
	if c := api(t, w, "GET", "/api/auth/magic?token="+mt, "", ""); c != 401 {
		t.Errorf("SECURITY T3 magic after issuer demotion: %d", c)
	}
	_ = w.svc.SetRoles(ctx, w.adminID, []string{"admin"})
	db, _ := w.svc.k.SQL(ctx)
	_, _ = db.Exec("DELETE FROM users WHERE id = "+w.svc.ph(1), w.adminID)
	if c := api(t, w, "GET", "/api/auth/magic?token="+mt2, "", ""); c != 401 {
		t.Errorf("SECURITY T4 magic after issuer deletion: %d", c)
	}
}

func TestReviewR4SessionsIssuedBeforePromotion(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	_, imp := impersonate(t, w, w.adminTok, w.userID)
	mag := magicSession(t, w, w.userID)
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/tokens", w.userTok, map[string]any{"name": "p", "abilities": []string{"*"}})
	pat, _ := asMap(t, b)["token"].(string)
	_ = w.svc.SetRoles(ctx, w.userID, []string{"admin"})
	for name, tk := range map[string]string{"impersonation": imp, "magic": mag, "pat": pat} {
		if tk == "" {
			continue
		}
		if c := api(t, w, "GET", "/api/auth/admin/users", tk, ""); c == 200 {
			t.Errorf("SECURITY T6 %s token gained admin API after promotion", name)
		}
	}
}

func TestReviewR4DeleteThenReRegister(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	b2, _ := w.svc.CreateUser(ctx, "gone@example.com", pw, []string{"admin"})
	old := tokFor(t, w.svc, "gone@example.com")
	if c := api(t, w, "DELETE", "/api/auth/admin/users/"+b2.ID, w.adminTok, ""); c != 200 {
		t.Fatalf("delete => %d", c)
	}
	if c := api(t, w, "GET", "/api/auth/admin/users", old, ""); c == 200 {
		t.Errorf("SECURITY T7 deleted admin token still reaches admin API")
	}
	api(t, w, "POST", "/api/auth/register", "", "{\"email\":\"gone@example.com\",\"password\":\"password-new-12\"}")
	if c := api(t, w, "GET", "/api/auth/admin/users", old, ""); c == 200 {
		t.Errorf("SECURITY T7 old token works for re-registered email")
	}
	if c := api(t, w, "GET", "/api/auth/me", old, ""); c != 401 {
		t.Errorf("deleted user's token accepted by /me: %d (strict revalidation must refuse it)", c)
	}
}

// TestReviewR4RacePromoteVsRedeem is a soak test: it races a promotion against
// a redemption many times. The deterministic proof of the same property is
// TestLifecycleResetRedeemVsPromoteLocked.
func TestReviewR4RacePromoteVsRedeem(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test")
	}
	w := newReviewWorld(t)
	ctx := context.Background()
	hits := 0
	for i := 0; i < 25; i++ {
		email := "race" + strconv.Itoa(i) + "@example.com"
		u, _ := w.svc.CreateUser(ctx, email, pw, nil)
		_, rt := adminLink(t, w, "reset-password", u.ID)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			api(t, w, "PATCH", "/api/auth/admin/users/"+u.ID, w.adminTok, "{\"roles\":[\"admin\"]}")
		}()
		go func() { defer wg.Done(); redeemReset(t, w, rt, "race-password-9") }()
		wg.Wait()
		got, _ := w.svc.userByID(ctx, u.ID)
		if got != nil && isAdminUser(got) && loginCode(t, w, email, "race-password-9") == 200 {
			hits++
		}
	}
	if hits > 0 {
		t.Errorf("FINDING F11: %d/25 rounds ended with an admin whose password was set via an admin-issued reset link (check-then-act race)", hits)
	}
}
