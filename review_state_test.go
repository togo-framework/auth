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

func TestReviewEmailUniquenessOnUpdate(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	patch := func(id, email string) int {
		c, _, _ := raw(t, w.srv, "PATCH", "/api/auth/admin/users/"+id, w.adminTok, map[string]any{"email": email})
		return c
	}
	for _, e := range []string{"root@example.com", "ROOT@example.com", "  root@example.com ", "Root@Example.COM"} {
		if c := patch(w.userID, e); c != 409 {
			t.Errorf("SECURITY duplicate email %q accepted: %d", e, c)
		}
	}
	db, _ := w.svc.k.SQL(ctx)
	q := "INSERT INTO users (id, email, password_hash, roles, permissions, created_at) VALUES (" + w.svc.ph(1) + "," + w.svc.ph(2) + "," + w.svc.ph(3) + "," + w.svc.ph(4) + "," + w.svc.ph(5) + "," + w.svc.ph(6) + ")"
	if _, err := db.Exec(q, "legacy1", "Legacy@Example.com", "x", "", "", "2020-01-01T00:00:00Z"); err != nil {
		t.Skipf("cannot seed legacy row: %v", err)
	}
	if c := patch(w.userID, "legacy@example.com"); c != 409 {
		t.Errorf("FINDING F5 (low): update to case-variant of legacy mixed-case email accepted (%d)", c)
	}
	c, _, _ := raw(t, w.srv, "POST", "/api/auth/admin/users", w.adminTok, map[string]any{"email": "LEGACY@example.com"})
	if c != 409 {
		t.Errorf("FINDING F5 (low): create of case-variant of legacy email accepted (%d)", c)
	}
}

func TestReviewLastAdminInvariant(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	base := "/api/auth/admin/users/"
	for _, roles := range [][]string{{}, {"Admin"}, {"admin2"}, {"editor"}} {
		if c, _, _ := raw(t, w.srv, "PATCH", base+w.adminID, w.adminTok, map[string]any{"roles": roles}); c != 409 {
			t.Errorf("SECURITY last admin demoted with roles=%v: %d", roles, c)
		}
	}
	if c, _, _ := raw(t, w.srv, "DELETE", base+w.adminID, w.adminTok, nil); c != 409 {
		t.Errorf("SECURITY last admin deleted: %d", c)
	}
	srv2, _ := bootSecond(t)
	b2, _ := w.svc.CreateUser(ctx, "b@example.com", pw, []string{"admin"})
	tokB := tokFor(t, w.svc, "b@example.com")
	for round := 0; round < 15; round++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			rawFrom(t, w.srv, "10.2.0."+strconv.Itoa(round), "PATCH", base+b2.ID, w.adminTok, "{\"roles\":[]}")
		}()
		go func() {
			defer wg.Done()
			rawFrom(t, srv2, "10.3.0."+strconv.Itoa(round), "PATCH", base+w.adminID, tokB, "{\"roles\":[]}")
		}()
		wg.Wait()
		n, err := w.svc.countAdmins(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			t.Errorf("FINDING F4: zero administrators after concurrent cross-instance demotion (round %d)", round)
			return
		}
		_ = w.svc.SetRoles(ctx, b2.ID, []string{"admin"})
		_ = w.svc.SetRoles(ctx, w.adminID, []string{"admin"})
	}
}

func TestReviewCSRFOnCookieWrites(t *testing.T) {
	w := newReviewWorld(t)
	_, tok := impersonate(t, w, w.adminTok, w.userID)
	do := func(method, path, body string, hdr map[string]string, cookies ...*http.Cookie) int {
		req, _ := http.NewRequest(method, w.srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	sess := &http.Cookie{Name: SessionCookie, Value: w.adminTok}
	id := w.userID
	writes := [][2]string{
		{"POST", "/api/auth/admin/users"},
		{"PATCH", "/api/auth/admin/users/" + id},
		{"DELETE", "/api/auth/admin/users/" + id},
		{"POST", "/api/auth/admin/users/" + id + "/impersonate"},
		{"POST", "/api/auth/admin/users/" + id + "/reset-password"},
		{"POST", "/api/auth/admin/users/" + id + "/magic-link"},
	}
	evil := map[string]string{"Origin": "https://evil.example"}
	for _, wr := range writes {
		if c := do(wr[0], wr[1], "{}", evil, sess); c != 403 {
			t.Errorf("SECURITY CSRF cross-origin %s %s => %d", wr[0], wr[1], c)
		}
		if c := do(wr[0], wr[1], "{}", nil, sess); c != 403 {
			t.Errorf("SECURITY CSRF no token %s %s => %d", wr[0], wr[1], c)
		}
		mm := map[string]string{"Origin": "https://evil.example", "X-CSRF-Token": "a"}
		if c := do(wr[0], wr[1], "{}", mm, sess, &http.Cookie{Name: csrfCookie, Value: "b"}); c != 403 {
			t.Errorf("SECURITY CSRF mismatched %s %s => %d", wr[0], wr[1], c)
		}
		bb := map[string]string{"Origin": "https://evil.example", "Authorization": "Bearer junk"}
		if c := do(wr[0], wr[1], "{}", bb, sess); c != 401 {
			t.Errorf("SECURITY bogus bearer plus cookie %s %s => %d", wr[0], wr[1], c)
		}
	}
	if c := do("POST", "/api/auth/impersonation/stop", "{}", evil, &http.Cookie{Name: SessionCookie, Value: tok}); c != 403 {
		t.Errorf("SECURITY CSRF on stop => %d", c)
	}
	if u, _ := w.svc.userByID(context.Background(), w.userID); u == nil {
		t.Errorf("forged request deleted the user")
	}
}

func TestReviewResetTokenConcurrentRedemption(t *testing.T) {
	w := newReviewWorld(t)
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, map[string]string{})
	rl, _ := asMap(t, b)["link"].(string)
	tok := rl[strings.Index(rl, "token=")+6:]
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := "{\"token\":\"" + tok + "\",\"password\":\"password-number-" + strconv.Itoa(i) + "\"}"
			c, _ := rawFrom(t, w.srv, "10.4.0."+strconv.Itoa(i), "POST", "/api/auth/password/reset", "", body)
			if c == 200 {
				atomic.AddInt32(&ok, 1)
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Errorf("FINDING F3: reset token redeemed %d times concurrently, want exactly 1", ok)
	}
}
