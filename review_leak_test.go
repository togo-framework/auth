package auth

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestReviewNoSecretsInLogsEventsOrErrors(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_PUBLIC_URL", "https://app.example.com")
	var secrets, bodies []string
	const newPw = "S3cret-admin-chosen-pw-77"
	tokOf := func(link string) string { return link[strings.Index(link, "token=")+6:] }

	_, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/magic-link", w.adminTok, map[string]string{})
	ml, _ := asMap(t, b)["link"].(string)
	secrets = append(secrets, tokOf(ml))
	_, b, _ = raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, map[string]string{})
	rl, _ := asMap(t, b)["link"].(string)
	secrets = append(secrets, tokOf(rl))
	_, tok := impersonate(t, w, w.adminTok, w.userID)
	secrets = append(secrets, tok)
	raw(t, w.srv, "GET", "/api/auth/magic?token="+secrets[0], "", nil)
	raw(t, w.srv, "POST", "/api/auth/admin/users", w.adminTok, map[string]any{"email": "newbie@example.com", "password": newPw})
	raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, map[string]string{"password": newPw + "x"})
	raw(t, w.srv, "POST", "/api/auth/impersonation/stop", tok, map[string]string{})
	secrets = append(secrets, newPw, newPw+"x", w.adminTok, w.userTok)

	cases := []struct{ m, p, body string }{
		{"POST", "/api/auth/admin/users", "{not json"},
		{"POST", "/api/auth/admin/users", strings.Repeat("x", 200000)},
		{"PATCH", "/api/auth/admin/users/" + w.userID, "[1,2,3]"},
		{"GET", "/api/auth/admin/users/%27%3B%20DROP%20TABLE%20users%3B--", ""},
		{"POST", "/api/auth/admin/users/nope/impersonate", "{}"},
	}
	for _, c := range cases {
		code, b, _ := raw(t, w.srv, c.m, c.p, w.adminTok, c.body)
		bodies = append(bodies, string(b))
		if code >= 500 {
			t.Errorf("%s %s => %d", c.m, c.p, code)
		}
	}
	db, _ := w.svc.k.SQL(context.Background())
	_, _ = db.Exec("DROP TABLE auth_magic_links")
	code, b, _ := raw(t, w.srv, "POST", "/api/auth/admin/users/"+w.userID+"/magic-link", w.adminTok, map[string]string{})
	bodies = append(bodies, string(b))
	if code != 500 {
		t.Logf("missing table gave %d", code)
	}
	for _, body := range bodies {
		for _, bad := range []string{"SQL", "sql:", "pgx", "sqlite", "no such table", "syntax", "relation ", "goroutine", ".go:"} {
			if strings.Contains(body, bad) {
				t.Errorf("SECURITY error body leaks internals (%q): %.200s", bad, body)
			}
		}
	}
	logs, events := w.log.String(), w.eventDump()
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(logs, s) {
			t.Errorf("SECURITY secret leaked into logs: %.12s", s)
		}
		if strings.Contains(events, s) {
			t.Errorf("SECURITY secret leaked into events: %.12s", s)
		}
	}
}

func TestReviewListInputHandling(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	for _, e := range []string{"a_b@example.com", "axb@example.com", "100%@example.com"} {
		if _, err := w.svc.CreateUser(ctx, e, pw, nil); err != nil {
			t.Fatal(err)
		}
	}
	count := func(q string) (int, int) {
		code, b, _ := raw(t, w.srv, "GET", "/api/auth/admin/users?"+q, w.adminTok, nil)
		return code, strings.Count(string(b), "\"id\"")
	}
	for _, c := range []struct {
		q string
		n int
	}{{"a_b", 1}, {"%", 1}} {
		if code, n := count("q=" + url.QueryEscape(c.q)); code != 200 || n != c.n {
			t.Errorf("FINDING (low) wildcard %q not literal: %d %d", c.q, code, n)
		}
	}
	odd := []string{"q=%27%20OR%201%3D1--", "q=%27%29%3B%20DROP%20TABLE%20users%3B--", "q=%00", "limit=-5",
		"limit=999999999999999999999", "offset=-1", "offset=99999999999", "limit=abc&offset=abc",
		"q=" + strings.Repeat("%C3%A9", 300), "q=%E2%82", "q=%FF%FE"}
	for _, q := range odd {
		if c, _ := count(q); c != 200 {
			t.Errorf("FINDING (low) list with %q => %d", q, c)
		}
	}
	if u, _ := w.svc.userByID(ctx, w.userID); u == nil {
		t.Errorf("users table damaged")
	}
	if c, n := count("limit=100000"); c != 200 || n > maxListLimit {
		t.Errorf("limit not capped: %d %d", c, n)
	}
}
