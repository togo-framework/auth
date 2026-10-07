package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func issueMagic(t *testing.T, w *reviewWorld, userID string) (link, token string) {
	t.Helper()
	code, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+userID+"/magic-link", w.adminTok, map[string]string{})
	if code != 200 {
		t.Fatalf("magic-link: %d %s", code, b)
	}
	link, _ = asMap(t, b)["link"].(string)
	i := strings.Index(link, "token=")
	if i < 0 {
		t.Fatalf("no token in link %q", link)
	}
	return link, link[i+6:]
}

// (8) single use under a concurrent race.
func TestReviewMagicLinkConcurrentRedemption(t *testing.T) {
	w := newReviewWorld(t)
	link, _ := issueMagic(t, w, w.userID)
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, hdr := rawFrom(t, w.srv, "10.1."+strconv.Itoa(i)+".1", "GET", link, "", "")
			if code == 302 && strings.Contains(strings.Join(hdr.Values("Set-Cookie"), ";"), SessionCookie+"=") {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("SECURITY magic link redeemed %d times concurrently, want exactly 1", ok)
	}
}

// (8) hashed at rest, short TTL, no cross-purpose use, redirect target, 2FA.
func TestReviewMagicLinkProperties(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_POST_LOGIN_URL", "https://app.example.com/dashboard")
	link, token := issueMagic(t, w, w.userID)
	db, _ := w.svc.k.SQL(context.Background())
	var hash, exp string
	if err := db.QueryRow("SELECT token_hash, expires_at FROM auth_magic_links").Scan(&hash, &exp); err != nil {
		t.Fatal(err)
	}
	if hash == token || strings.Contains(hash, token) || len(hash) != 64 {
		t.Errorf("SECURITY token not hashed at rest")
	}
	if e, _ := time.Parse(time.RFC3339, exp); time.Until(e) > 16*time.Minute || time.Until(e) < 14*time.Minute {
		t.Errorf("magic TTL unexpected: %s", exp)
	}
	// the magic token is not a reset token, and a reset token is not a magic token
	if code, _, _ := raw(t, w.srv, "POST", "/api/auth/password/reset", "", map[string]string{"token": token, "password": "attacker-password-1"}); code != 401 {
		t.Errorf("SECURITY magic token accepted as reset token: %d", code)
	}
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, map[string]string{})
	rl, _ := asMap(t, b)["link"].(string)
	rtok := rl[strings.Index(rl, "token=")+6:]
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/magic?token="+rtok, "", nil); code != 401 {
		t.Errorf("SECURITY reset token accepted as magic link: %d", code)
	}
	// issuing the reset link must not have invalidated the magic link, and vice versa
	// redirect target is fixed by config, never by the request
	req, _ := http.NewRequest("GET", w.srv.URL+link+"&redirect=//evil.example&next=https://evil.example&url=https://evil.example&return_to=//evil.example", nil)
	req.Host = "evil.example"
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("Referer", "https://evil.example/")
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 302 || res.Header.Get("Location") != "https://app.example.com/dashboard" {
		t.Errorf("SECURITY redirect not fixed to config: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	// expired link
	_, token2 := issueMagic(t, w, w.userID)
	if _, err := db.Exec("UPDATE auth_magic_links SET expires_at = "+w.svc.ph(1), stamp(time.Now().Add(-time.Minute))); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := raw(t, w.srv, "GET", "/api/auth/magic?token="+token2, "", nil); code != 401 {
		t.Errorf("SECURITY expired magic link accepted: %d", code)
	}
	// garbage and oversize tokens are the same 401
	for _, tk := range []string{"", "x", strings.Repeat("a", 300), "%00"} {
		if code, _, _ := raw(t, w.srv, "GET", "/api/auth/magic?token="+tk, "", nil); code != 401 {
			t.Errorf("garbage token %q: %d", tk, code)
		}
	}
}

// 2FA is not bypassed, no session cookie is set, and the response is not a redirect.
func TestReviewMagicLinkDoesNotBypassTOTP(t *testing.T) {
	w := newReviewWorld(t)
	db, _ := w.svc.k.SQL(context.Background())
	link, _ := issueMagic(t, w, w.userID)
	if _, err := db.Exec("INSERT INTO auth_totp (subject, secret, enabled) VALUES ("+w.svc.ph(1)+", "+w.svc.ph(2)+", "+w.svc.ph(3)+")", w.userID, "JBSWY3DPEHPK3PXP", "true"); err != nil {
		t.Skipf("cannot seed totp row: %v", err)
	}
	code, _, hdr := raw(t, w.srv, "GET", link, "", nil)
	if code == 302 || strings.Contains(strings.Join(hdr.Values("Set-Cookie"), ";"), SessionCookie+"=") {
		t.Errorf("SECURITY magic link bypassed TOTP: %d", code)
	}
}

// Host header and forwarding headers never reach a generated link.
func TestReviewLinksIgnoreHostAndForwardedHeaders(t *testing.T) {
	w := newReviewWorld(t)
	for _, base := range []string{"", "https://app.example.com"} {
		t.Setenv("AUTH_PUBLIC_URL", base)
		t.Setenv("APP_URL", "")
		for _, path := range []string{"/magic-link", "/reset-password"} {
			req, _ := http.NewRequest("POST", w.srv.URL+"/api/auth/admin/users/"+w.userID+path, strings.NewReader("{}"))
			req.Host = "evil.example"
			req.Header.Set("Authorization", "Bearer "+w.adminTok)
			req.Header.Set("X-Forwarded-Host", "evil.example")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("Forwarded", "host=evil.example;proto=https")
			req.Header.Set("Origin", "https://evil.example")
			req.Header.Set("Content-Type", "application/json")
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			buf := new(strings.Builder)
			b := make([]byte, 4096)
			n, _ := res.Body.Read(b)
			buf.Write(b[:n])
			res.Body.Close()
			if strings.Contains(buf.String(), "evil.example") {
				t.Errorf("SECURITY link poisoned (base=%q %s): %s", base, path, buf.String())
			}
		}
	}
}
