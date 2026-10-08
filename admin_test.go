package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---- helpers -------------------------------------------------------------

// raw sends one request with no cookie jar and an optional bearer token.
func raw(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte, http.Header) {
	t.Helper()
	var rdr io.Reader
	if s, ok := body.(string); ok {
		rdr = strings.NewReader(s)
	} else if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out, res.Header
}

func asMap(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not a JSON object: %s", b)
	}
	return m
}

type adminWorld struct {
	srv       *httptest.Server
	svc       *Service
	adminID   string
	adminTok  string
	userID    string
	userTok   string
	adminMail string
}

func loginToken(t *testing.T, srv *httptest.Server, email string) string {
	t.Helper()
	code, b, _ := raw(t, srv, http.MethodPost, "/api/auth/login", "", map[string]string{"email": email, "password": pw})
	if code != http.StatusOK {
		t.Fatalf("login %s: %d %s", email, code, b)
	}
	tok, _ := asMap(t, b)["token"].(string)
	if tok == "" {
		t.Fatalf("login %s: no token: %s", email, b)
	}
	return tok
}

func newAdminWorld(t *testing.T) *adminWorld {
	t.Helper()
	srv, svc := bootAuth(t)
	ctx := context.Background()
	admin, err := svc.CreateUser(ctx, "root@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := svc.CreateUser(ctx, "bob@example.com", pw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &adminWorld{
		srv: srv, svc: svc,
		adminID: admin.ID, adminTok: loginToken(t, srv, "root@example.com"),
		userID: user.ID, userTok: loginToken(t, srv, "bob@example.com"),
		adminMail: "root@example.com",
	}
}

func (w *adminWorld) capture(event string) *[]any {
	var got []any
	w.svc.k.Hooks.On(event, 50, func(_ context.Context, p any) error {
		got = append(got, p)
		return nil
	})
	return &got
}

func jwtClaims(t *testing.T, tok string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

// ---- authorization: authenticated is NOT administrator ---------------------

type adminRoute struct{ method, path string }

func adminRoutes(id string) []adminRoute {
	u := "/api/auth/admin/users"
	return []adminRoute{
		{http.MethodGet, u},
		{http.MethodPost, u},
		{http.MethodGet, u + "/" + id},
		{http.MethodPatch, u + "/" + id},
		{http.MethodDelete, u + "/" + id},
		{http.MethodPost, u + "/" + id + "/impersonate"},
		{http.MethodPost, u + "/" + id + "/reset-password"},
		{http.MethodPost, u + "/" + id + "/magic-link"},
	}
}

func TestAdminRoutesRequireAdministrator(t *testing.T) {
	w := newAdminWorld(t)
	for _, rt := range adminRoutes(w.userID) {
		name := rt.method + " " + rt.path
		t.Run("anonymous "+name, func(t *testing.T) {
			if code, _, _ := raw(t, w.srv, rt.method, rt.path, "", map[string]string{}); code != http.StatusUnauthorized {
				t.Fatalf("anonymous must get 401, got %d", code)
			}
		})
		t.Run("garbage token "+name, func(t *testing.T) {
			if code, _, _ := raw(t, w.srv, rt.method, rt.path, "not-a-token", map[string]string{}); code != http.StatusUnauthorized {
				t.Fatalf("a bad token must get 401, got %d", code)
			}
		})
		t.Run("authenticated non-admin "+name, func(t *testing.T) {
			if code, b, _ := raw(t, w.srv, rt.method, rt.path, w.userTok, map[string]string{}); code != http.StatusForbidden {
				t.Fatalf("SECURITY: a normal user must get 403, got %d %s", code, b)
			}
		})
	}
	// The user is untouched by all those attempts.
	if u, _ := w.svc.userByID(context.Background(), w.userID); u == nil || u.Roles != "" {
		t.Fatalf("a refused request must not change anything: %+v", u)
	}
}

func TestAdminRoutesAllowAdministrator(t *testing.T) {
	w := newAdminWorld(t)
	if code, b, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users", w.adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin list: %d %s", code, b)
	}
	if code, b, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users/"+w.userID, w.adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin get: %d %s", code, b)
	}
}

// The role is re-read from the database on every request: a token minted while
// the user was an admin stops working the moment they are demoted or deleted.
func TestAdminRoleIsCheckedAgainstTheDatabase(t *testing.T) {
	w := newAdminWorld(t)
	second, err := w.svc.CreateUser(context.Background(), "second@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	tok := loginToken(t, w.srv, "second@example.com")
	list := "/api/auth/admin/users"
	if code, _, _ := raw(t, w.srv, http.MethodGet, list, tok, nil); code != http.StatusOK {
		t.Fatalf("precondition: %d", code)
	}
	if err := w.svc.SetRoles(context.Background(), second.ID, nil); err != nil {
		t.Fatal(err)
	}
	if !jwtClaimsHaveAdmin(t, tok) {
		t.Fatal("test setup: the token should still claim admin")
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, list, tok, nil); code != http.StatusForbidden {
		t.Fatalf("SECURITY: a demoted admin kept access via a stale token claim: %d", code)
	}
	if err := w.svc.SetRoles(context.Background(), second.ID, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	code, _, _ := raw(t, w.srv, http.MethodDelete, list+"/"+second.ID, w.adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("delete second admin: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, list, tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a deleted admin's token must be refused with 401, got %d", code)
	}
}

func jwtClaimsHaveAdmin(t *testing.T, tok string) bool {
	return strings.Contains(fmt.Sprint(jwtClaims(t, tok)["roles"]), "admin")
}

// A personal access token carries the owner's id but is scoped by abilities;
// it must not inherit the owner's admin role.
func TestAdminRoutesRefuseAPITokens(t *testing.T) {
	w := newAdminWorld(t)
	code, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/tokens", w.adminTok, map[string]any{"name": "ci", "abilities": []string{"posts.read"}})
	if code != http.StatusCreated {
		t.Fatalf("create pat: %d %s", code, b)
	}
	pat, _ := asMap(t, b)["token"].(string)
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users", pat, nil); code != http.StatusForbidden {
		t.Fatalf("an API token must not reach the admin API, got %d", code)
	}
}

// ---- CSRF ----------------------------------------------------------------

func TestAdminWritesRequireCSRFForCookieSessions(t *testing.T) {
	w := newAdminWorld(t)
	c := newClient(t, w.srv)
	if code := c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": w.adminMail, "password": pw}, nil); code != http.StatusOK {
		t.Fatalf("cookie login: %d", code)
	}
	body := `{"email":"new@example.com","password":"` + pw + `"}`
	post := func(csrf string) int {
		req, _ := http.NewRequest(http.MethodPost, w.srv.URL+"/api/auth/admin/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, err := c.http.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if code := post(""); code != http.StatusForbidden {
		t.Fatalf("a cookie-authenticated write without a CSRF token must be 403, got %d", code)
	}
	if code := post("wrong"); code != http.StatusForbidden {
		t.Fatalf("a wrong CSRF token must be 403, got %d", code)
	}
	if code := post(c.csrf); code != http.StatusCreated {
		t.Fatalf("with the CSRF token the write must succeed, got %d", code)
	}
	// Bearer requests are exempt, like the rest of the plugin.
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users", w.adminTok, map[string]string{"email": "bearer@example.com"}); code != http.StatusCreated {
		t.Fatalf("bearer write: %d", code)
	}
}

// ---- CRUD ----------------------------------------------------------------

func TestAdminUserCRUD(t *testing.T) {
	w := newAdminWorld(t)
	base := "/api/auth/admin/users"
	created := w.capture(EventUserCreated)
	updated := w.capture(EventUserUpdated)
	deleted := w.capture(EventUserDeleted)

	code, b, _ := raw(t, w.srv, http.MethodPost, base, w.adminTok, map[string]any{"email": "  New@Example.com ", "password": pw, "roles": []string{"editor"}})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, b)
	}
	user := asMap(t, b)["user"].(map[string]any)
	id := user["id"].(string)
	if user["email"] != "new@example.com" || fmt.Sprint(user["roles"]) != "[editor]" {
		t.Fatalf("created user: %v", user)
	}
	if strings.Contains(string(b), "password") {
		t.Fatalf("no password material in responses: %s", b)
	}
	loginToken(t, w.srv, "new@example.com") // the password works

	if code, _, _ := raw(t, w.srv, http.MethodPost, base, w.adminTok, map[string]any{"email": "NEW@example.com"}); code != http.StatusConflict {
		t.Fatalf("duplicate email: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, base, w.adminTok, map[string]any{"email": "not-an-email"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid email: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, base, w.adminTok, map[string]any{"email": "weak@example.com", "password": "short"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("weak password: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, base, w.adminTok, map[string]any{"email": "r@example.com", "roles": []string{"a,b"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("a role containing a comma would forge a second role: %d", code)
	}

	// A passwordless account can be created (to be given a link) but cannot log in.
	if code, _, _ := raw(t, w.srv, http.MethodPost, base, w.adminTok, map[string]any{"email": "nopw@example.com"}); code != http.StatusCreated {
		t.Fatalf("passwordless create: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/login", "", map[string]string{"email": "nopw@example.com", "password": "!sso"}); code != http.StatusUnauthorized {
		t.Fatalf("a passwordless account must not be loginable: %d", code)
	}

	code, b, _ = raw(t, w.srv, http.MethodGet, base+"/"+id, w.adminTok, nil)
	if code != http.StatusOK || asMap(t, b)["email"] != "new@example.com" {
		t.Fatalf("get: %d %s", code, b)
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, base+"/does-not-exist", w.adminTok, nil); code != http.StatusNotFound {
		t.Fatalf("missing user: %d", code)
	}

	// Search.
	code, b, _ = raw(t, w.srv, http.MethodGet, base+"?q=NEW@", w.adminTok, nil)
	var list []map[string]any
	if code != http.StatusOK || json.Unmarshal(b, &list) != nil || len(list) != 1 {
		t.Fatalf("search: %d %s", code, b)
	}
	// A wildcard in the query is literal, not a pattern.
	code, b, _ = raw(t, w.srv, http.MethodGet, base+"?q="+url.QueryEscape("%"), w.adminTok, nil)
	if json.Unmarshal(b, &list) != nil || len(list) != 0 {
		t.Fatalf("q=%% must match nothing literal: %d %s", code, b)
	}

	// Update: email uniqueness, roles, permissions.
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base+"/"+id, w.adminTok, map[string]any{"email": "bob@example.com"}); code != http.StatusConflict {
		t.Fatalf("taking another user's email: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base+"/"+id, w.adminTok, map[string]any{"email": "bad"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid email on update: %d", code)
	}
	code, b, _ = raw(t, w.srv, http.MethodPatch, base+"/"+id, w.adminTok, map[string]any{"email": "renamed@example.com", "roles": []string{"editor", "reviewer"}, "permissions": []string{"posts.write"}})
	if code != http.StatusOK {
		t.Fatalf("update: %d %s", code, b)
	}
	got := asMap(t, b)
	if got["email"] != "renamed@example.com" || fmt.Sprint(got["roles"]) != "[editor reviewer]" || fmt.Sprint(got["permissions"]) != "[posts.write]" {
		t.Fatalf("updated user: %v", got)
	}
	// Setting the same email again is not a conflict with oneself.
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base+"/"+id, w.adminTok, map[string]any{"email": "Renamed@example.com"}); code != http.StatusOK {
		t.Fatalf("idempotent email update: %d", code)
	}

	// Malformed body: a generic message, never the decoder's text.
	code, b, _ = raw(t, w.srv, http.MethodPatch, base+"/"+id, w.adminTok, "{not json")
	if code != http.StatusBadRequest || strings.Contains(string(b), "invalid character") {
		t.Fatalf("malformed body must be a generic 400: %d %s", code, b)
	}

	if code, _, _ := raw(t, w.srv, http.MethodDelete, base+"/"+id, w.adminTok, nil); code != http.StatusOK {
		t.Fatalf("delete: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, base+"/"+id, w.adminTok, nil); code != http.StatusNotFound {
		t.Fatalf("deleted user must be gone: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodDelete, base+"/"+id, w.adminTok, nil); code != http.StatusNotFound {
		t.Fatalf("deleting twice: %d", code)
	}
	if len(*created) < 1 || len(*updated) < 1 || len(*deleted) != 1 {
		t.Fatalf("events: created=%d updated=%d deleted=%d", len(*created), len(*updated), len(*deleted))
	}
	ev := (*deleted)[0].(map[string]string)
	if ev["actor_id"] != w.adminID || ev["user_id"] != id {
		t.Fatalf("delete event must carry actor and target: %v", ev)
	}
}

// Users past the first page are reachable by listing with an offset and by id.
func TestAdminListIsPaginatedAndReachesEveryUser(t *testing.T) {
	w := newAdminWorld(t)
	db, _ := w.svc.k.SQL(context.Background())
	const extra = 520
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < extra; i++ {
		if _, err := tx.Exec("INSERT INTO users (id, email, password_hash, roles, permissions, created_at) VALUES ("+w.svc.ph(1)+","+w.svc.ph(2)+",'x','','',"+w.svc.ph(3)+")",
			fmt.Sprintf("bulk-%04d", i), fmt.Sprintf("bulk%04d@example.com", i), fmt.Sprintf("2020-01-01T00:%02d:%02dZ", i/60%60, i%60)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var page []map[string]any
	code, b, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users?limit=10&offset=0", w.adminTok, nil)
	if code != http.StatusOK || json.Unmarshal(b, &page) != nil || len(page) != 10 {
		t.Fatalf("page 1: %d len=%d", code, len(page))
	}
	seen := map[string]bool{}
	for off := 0; ; off += 200 {
		code, b, _ = raw(t, w.srv, http.MethodGet, fmt.Sprintf("/api/auth/admin/users?limit=200&offset=%d", off), w.adminTok, nil)
		if code != http.StatusOK || json.Unmarshal(b, &page) != nil {
			t.Fatalf("page at %d: %d", off, code)
		}
		if len(page) == 0 {
			break
		}
		for _, u := range page {
			seen[u["id"].(string)] = true
		}
	}
	if len(seen) != extra+2 {
		t.Fatalf("paging must reach every user: saw %d of %d", len(seen), extra+2)
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users/bulk-0000", w.adminTok, nil); code != http.StatusOK {
		t.Fatalf("a user beyond the first 500 must be reachable by id: %d", code)
	}
	// An absurd limit is clamped, not honoured.
	code, b, _ = raw(t, w.srv, http.MethodGet, "/api/auth/admin/users?limit=100000", w.adminTok, nil)
	if code != http.StatusOK || json.Unmarshal(b, &page) != nil || len(page) > 500 {
		t.Fatalf("limit must be clamped: %d len=%d", code, len(page))
	}
}

func TestLastAdminCannotBeDeletedOrDemoted(t *testing.T) {
	w := newAdminWorld(t)
	base := "/api/auth/admin/users/" + w.adminID
	if code, _, _ := raw(t, w.srv, http.MethodDelete, base, w.adminTok, nil); code != http.StatusConflict {
		t.Fatalf("deleting the last admin: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base, w.adminTok, map[string]any{"roles": []string{"editor"}}); code != http.StatusConflict {
		t.Fatalf("demoting the last admin: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base, w.adminTok, map[string]any{"roles": []string{}}); code != http.StatusConflict {
		t.Fatalf("clearing the last admin's roles: %d", code)
	}
	// Other fields on the last admin are fine, and keeping the role is fine.
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base, w.adminTok, map[string]any{"roles": []string{"admin", "editor"}}); code != http.StatusOK {
		t.Fatalf("keeping admin: %d", code)
	}
	// "superadmin" is not "admin".
	if _, err := w.svc.CreateUser(context.Background(), "sup@example.com", pw, []string{"superadmin"}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := raw(t, w.srv, http.MethodDelete, base, w.adminTok, nil); code != http.StatusConflict {
		t.Fatalf("a superadmin must not count as an admin: %d", code)
	}
	// With a second admin, the first can be demoted.
	if _, err := w.svc.CreateUser(context.Background(), "two@example.com", pw, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base, w.adminTok, map[string]any{"roles": []string{}}); code != http.StatusOK {
		t.Fatalf("demoting with a second admin present: %d", code)
	}
}

// ---- password reset + magic links -----------------------------------------

func TestAdminSetPassword(t *testing.T) {
	w := newAdminWorld(t)
	ev := w.capture(EventPasswordChanged)
	p := "/api/auth/admin/users/" + w.userID + "/reset-password"
	if code, _, _ := raw(t, w.srv, http.MethodPost, p, w.adminTok, map[string]string{"password": "short"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("policy applies: %d", code)
	}
	code, b, _ := raw(t, w.srv, http.MethodPost, p, w.adminTok, map[string]string{"password": "a-brand-new-passphrase"})
	if code != http.StatusOK || asMap(t, b)["reset"] != true {
		t.Fatalf("set password: %d %s", code, b)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/login", "", map[string]string{"email": "bob@example.com", "password": "a-brand-new-passphrase"}); code != http.StatusOK {
		t.Fatalf("login with the new password: %d", code)
	}
	if len(*ev) != 1 || (*ev)[0].(map[string]string)["actor_id"] != w.adminID {
		t.Fatalf("password change event must name the actor: %v", *ev)
	}
}

func TestResetLinkIsSingleUseExpiringAndNeverInEvents(t *testing.T) {
	t.Setenv("AUTH_PUBLIC_URL", "https://app.example.com/")
	w := newAdminWorld(t)
	events := w.capture(EventAdminResetLinkIssued)
	p := "/api/auth/admin/users/" + w.userID + "/reset-password"

	code, b, _ := raw(t, w.srv, http.MethodPost, p, w.adminTok, map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("reset link: %d %s", code, b)
	}
	res := asMap(t, b)
	link, _ := res["link"].(string)
	if !strings.HasPrefix(link, "https://app.example.com/") || res["emailed"] != false {
		t.Fatalf("link must use the configured base: %v", res)
	}
	u, _ := url.Parse(link)
	token := u.Query().Get("token")
	if token == "" {
		t.Fatalf("no token in link %q", link)
	}
	if len(*events) != 1 {
		t.Fatalf("one event expected, got %d", len(*events))
	}
	if strings.Contains(fmt.Sprint((*events)[0]), token) {
		t.Fatalf("SECURITY: the raw token leaked into an event payload: %v", (*events)[0])
	}
	if (*events)[0].(map[string]string)["actor_id"] != w.adminID {
		t.Fatalf("event must name the actor: %v", (*events)[0])
	}

	// Issuing a second link retires the first.
	_, b, _ = raw(t, w.srv, http.MethodPost, p, w.adminTok, map[string]string{})
	u2, _ := url.Parse(asMap(t, b)["link"].(string))
	token2 := u2.Query().Get("token")
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/password/reset", "", map[string]string{"token": token, "password": "first-attempt-passphrase"}); code != http.StatusUnauthorized {
		t.Fatalf("a superseded link must be dead: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/password/reset", "", map[string]string{"token": token2, "password": "second-attempt-passphrase"}); code != http.StatusOK {
		t.Fatalf("the latest link must work once: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/password/reset", "", map[string]string{"token": token2, "password": "third-attempt-passphrase"}); code != http.StatusUnauthorized {
		t.Fatalf("a used link must be dead: %d", code)
	}

	// Expiry.
	_, b, _ = raw(t, w.srv, http.MethodPost, p, w.adminTok, map[string]string{})
	u3, _ := url.Parse(asMap(t, b)["link"].(string))
	db, _ := w.svc.k.SQL(context.Background())
	if _, err := db.Exec("UPDATE auth_password_resets SET expires_at = "+w.svc.ph(1), time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/password/reset", "", map[string]string{"token": u3.Query().Get("token"), "password": "expired-attempt-passphrase"}); code != http.StatusUnauthorized {
		t.Fatalf("an expired link must be dead: %d", code)
	}
}

func TestLinksNeverTrustTheHostHeader(t *testing.T) {
	w := newAdminWorld(t) // no AUTH_PUBLIC_URL / APP_URL configured
	for _, suffix := range []string{"magic-link", "reset-password"} {
		req, _ := http.NewRequest(http.MethodPost, w.srv.URL+"/api/auth/admin/users/"+w.userID+"/"+suffix, strings.NewReader("{}"))
		req.Host = "evil.example"
		req.Header.Set("X-Forwarded-Host", "evil.example")
		req.Header.Set("Authorization", "Bearer "+w.adminTok)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		link, _ := asMap(t, b)["link"].(string)
		if res.StatusCode != http.StatusOK || !strings.HasPrefix(link, "/") || strings.Contains(link, "evil") || strings.Contains(link, "://") {
			t.Fatalf("%s: with no configured base the link must be a relative path: %d %s", suffix, res.StatusCode, b)
		}
	}
	// A misconfigured (non-http) base is ignored rather than trusted.
	t.Setenv("AUTH_PUBLIC_URL", "javascript:alert(1)")
	_, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+w.userID+"/magic-link", w.adminTok, map[string]string{})
	if link, _ := asMap(t, b)["link"].(string); !strings.HasPrefix(link, "/") {
		t.Fatalf("an invalid base must fall back to a relative path: %s", b)
	}
}

func TestMagicLinkIsSingleUseExpiringAndSignsTheUserIn(t *testing.T) {
	t.Setenv("AUTH_PUBLIC_URL", "https://app.example.com")
	t.Setenv("AUTH_POST_LOGIN_URL", "/dashboard")
	w := newAdminWorld(t)
	events := w.capture(EventMagicLinkIssued)
	m := "/api/auth/admin/users/" + w.userID + "/magic-link"

	code, b, _ := raw(t, w.srv, http.MethodPost, m, w.adminTok, map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("magic link: %d %s", code, b)
	}
	res := asMap(t, b)
	link := res["link"].(string)
	u, _ := url.Parse(link)
	token := u.Query().Get("token")
	if !strings.HasPrefix(link, "https://app.example.com/api/auth/magic?token=") || token == "" || res["expires_at"] == nil {
		t.Fatalf("link shape: %v", res)
	}
	if len(*events) != 1 || strings.Contains(fmt.Sprint((*events)[0]), token) || strings.Contains(fmt.Sprint((*events)[0]), "http") {
		t.Fatalf("SECURITY: event must not carry the link or token: %v", *events)
	}
	if exp, _ := time.Parse(time.RFC3339, res["expires_at"].(string)); time.Until(exp) > 30*time.Minute || time.Until(exp) < time.Minute {
		t.Fatalf("a magic link must be short-lived, expires_at=%v", res["expires_at"])
	}

	// A token is not a password-reset token (purpose-bound).
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/password/reset", "", map[string]string{"token": token, "password": "stolen-purpose-passphrase"}); code != http.StatusUnauthorized {
		t.Fatalf("a magic token must not reset a password: %d", code)
	}

	consume := func(tok string) (int, http.Header) {
		code, _, h := raw(t, w.srv, http.MethodGet, "/api/auth/magic?token="+url.QueryEscape(tok), "", nil)
		return code, h
	}
	code, h := consume(token)
	if code != http.StatusFound || h.Get("Location") != "/dashboard" {
		t.Fatalf("consume: %d %v", code, h)
	}
	if !strings.Contains(strings.Join(h.Values("Set-Cookie"), ";"), SessionCookie+"=") {
		t.Fatalf("consuming must start a session: %v", h)
	}
	if code, _ := consume(token); code != http.StatusUnauthorized {
		t.Fatalf("a magic link must work once, second use: %d", code)
	}
	if code, _ := consume("forged"); code != http.StatusUnauthorized {
		t.Fatalf("forged token: %d", code)
	}
	if code, _ := consume(""); code != http.StatusUnauthorized {
		t.Fatalf("empty token: %d", code)
	}

	// Expiry.
	_, b, _ = raw(t, w.srv, http.MethodPost, m, w.adminTok, map[string]string{})
	u2, _ := url.Parse(asMap(t, b)["link"].(string))
	db, _ := w.svc.k.SQL(context.Background())
	if _, err := db.Exec("UPDATE auth_magic_links SET expires_at = "+w.svc.ph(1), time.Now().Add(-time.Second).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if code, _ := consume(u2.Query().Get("token")); code != http.StatusUnauthorized {
		t.Fatalf("an expired magic link must be refused: %d", code)
	}
}

func TestMagicLinkDoesNotBypassTwoFactor(t *testing.T) {
	w := newAdminWorld(t)
	c := newClient(t, w.srv)
	register(t, c, "guarded@example.com")
	enable2FA(t, c, "guarded@example.com")
	u, _ := w.svc.userByEmail(context.Background(), "guarded@example.com")
	_, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+u.ID+"/magic-link", w.adminTok, map[string]string{})
	link := asMap(t, b)["link"].(string)
	code, _, h := raw(t, w.srv, http.MethodGet, link, "", nil)
	if code == http.StatusFound || strings.Contains(strings.Join(h.Values("Set-Cookie"), ";"), SessionCookie+"=") {
		t.Fatalf("SECURITY: a magic link signed in a 2FA user without the second factor: %d", code)
	}
}

// ---- impersonation ---------------------------------------------------------

func TestImpersonationIssuesADistinguishableShortLivedAuditedToken(t *testing.T) {
	w := newAdminWorld(t)
	events := w.capture(EventUserImpersonated)
	before := time.Now()

	code, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+w.userID+"/impersonate", w.adminTok, nil)
	if code != http.StatusOK {
		t.Fatalf("impersonate: %d %s", code, b)
	}
	res := asMap(t, b)
	tok, _ := res["token"].(string)
	ident := res["identity"].(map[string]any)
	if tok == "" || ident["id"] != w.userID || ident["email"] != "bob@example.com" || ident["impersonator"] != w.adminID {
		t.Fatalf("response: %v", res)
	}

	claims := jwtClaims(t, tok)
	act, _ := claims["act"].(map[string]any)
	if claims["sub"] != w.userID || act["sub"] != w.adminID || claims["jti"] == nil || claims["jti"] == "" {
		t.Fatalf("token must name subject, actor and a jti: %v", claims)
	}
	exp := time.Unix(int64(claims["exp"].(float64)), 0)
	if exp.Sub(before) > 31*time.Minute || exp.Before(before) {
		t.Fatalf("impersonation must be short-lived (<= 30m default), exp in %v", exp.Sub(before))
	}

	// /me tells the dashboard it is an impersonation.
	code, b, _ = raw(t, w.srv, http.MethodGet, "/api/auth/me", tok, nil)
	me := asMap(t, b)
	if code != http.StatusOK || me["id"] != w.userID || me["impersonator"] != w.adminID {
		t.Fatalf("me while impersonating: %d %v", code, me)
	}
	code, b, _ = raw(t, w.srv, http.MethodGet, "/api/auth/me", w.adminTok, nil)
	if _, has := asMap(t, b)["impersonator"]; has || code != http.StatusOK {
		t.Fatalf("a real login must carry no impersonator: %s", b)
	}

	if len(*events) != 1 {
		t.Fatalf("one audit event expected: %v", *events)
	}
	ev := (*events)[0].(map[string]string)
	if ev["actor_id"] != w.adminID || ev["target_id"] != w.userID || ev["at"] == "" {
		t.Fatalf("audit event: %v", ev)
	}
	if strings.Contains(fmt.Sprint(ev), tok) {
		t.Fatal("SECURITY: the token must not be in the audit event")
	}

	// An impersonated session never reaches the admin API, and cannot change the
	// credentials of the account it is borrowing.
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users", tok, nil); code != http.StatusForbidden {
		t.Fatalf("impersonated sessions must not use the admin API: %d", code)
	}
	for _, rt := range []adminRoute{
		{http.MethodPost, "/api/auth/change-password"},
		{http.MethodPost, "/api/auth/2fa/enroll"},
		{http.MethodPost, "/api/auth/2fa/disable"},
		{http.MethodPost, "/api/auth/pin"},
		{http.MethodPost, "/api/auth/tokens"},
	} {
		if code, _, _ := raw(t, w.srv, rt.method, rt.path, tok, map[string]string{"name": "x", "old_password": pw, "new_password": "another-long-passphrase"}); code != http.StatusForbidden {
			t.Fatalf("%s must refuse an impersonated session, got %d", rt.path, code)
		}
	}
}

func TestImpersonationAdminPolicy(t *testing.T) {
	w := newAdminWorld(t)
	other, err := w.svc.CreateUser(context.Background(), "other@example.com", pw, []string{"editor", "admin"})
	if err != nil {
		t.Fatal(err)
	}
	imp := func(id string) int {
		code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+id+"/impersonate", w.adminTok, nil)
		return code
	}
	if code := imp(other.ID); code != http.StatusForbidden {
		t.Fatalf("impersonating another admin must be refused by default: %d", code)
	}
	if code := imp(w.adminID); code != http.StatusBadRequest {
		t.Fatalf("impersonating yourself is pointless: %d", code)
	}
	if code := imp("missing"); code != http.StatusNotFound {
		t.Fatalf("unknown target: %d", code)
	}
	t.Setenv("AUTH_ADMIN_CROSS_CONTROL", "true")
	if code := imp(other.ID); code != http.StatusOK {
		t.Fatalf("allowed by config: %d", code)
	}
}

func TestImpersonationTTLIsConfigurableAndCapped(t *testing.T) {
	w := newAdminWorld(t)
	ttl := func() time.Duration {
		_, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+w.userID+"/impersonate", w.adminTok, nil)
		c := jwtClaims(t, asMap(t, b)["token"].(string))
		return time.Unix(int64(c["exp"].(float64)), 0).Sub(time.Unix(int64(c["iat"].(float64)), 0))
	}
	t.Setenv("AUTH_IMPERSONATION_TTL_MINUTES", "5")
	if d := ttl(); d != 5*time.Minute {
		t.Fatalf("configured ttl: %v", d)
	}
	t.Setenv("AUTH_IMPERSONATION_TTL_MINUTES", "99999")
	if d := ttl(); d > 8*time.Hour {
		t.Fatalf("ttl must be capped: %v", d)
	}
}

func TestStopImpersonationRevokesTheTokenAndAudits(t *testing.T) {
	w := newAdminWorld(t)
	ended := w.capture(EventImpersonationEnded)
	_, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+w.userID+"/impersonate", w.adminTok, nil)
	tok := asMap(t, b)["token"].(string)

	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/impersonation/stop", w.adminTok, nil); code != http.StatusBadRequest {
		t.Fatalf("stop without impersonating: %d", code)
	}
	if code, _, _ := raw(t, w.srv, http.MethodPost, "/api/auth/impersonation/stop", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("stop anonymous: %d", code)
	}
	code, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/impersonation/stop", tok, nil)
	if code != http.StatusOK || asMap(t, b)["status"] != "ok" {
		t.Fatalf("stop: %d %s", code, b)
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/me", tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("a stopped impersonation token must be dead: %d", code)
	}
	if len(*ended) != 1 {
		t.Fatalf("end audit event: %v", *ended)
	}
	ev := (*ended)[0].(map[string]string)
	if ev["actor_id"] != w.adminID || ev["target_id"] != w.userID {
		t.Fatalf("end event: %v", ev)
	}
	// The admin's own session is unaffected.
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/admin/users", w.adminTok, nil); code != http.StatusOK {
		t.Fatalf("admin session after stop: %d", code)
	}
}

// If the admin who started an impersonation loses the role, the borrowed
// session dies with it.
func TestImpersonationDiesWhenTheActorIsNoLongerAdmin(t *testing.T) {
	w := newAdminWorld(t)
	if _, err := w.svc.CreateUser(context.Background(), "keeper@example.com", pw, []string{"admin"}); err != nil {
		t.Fatal(err)
	}
	_, b, _ := raw(t, w.srv, http.MethodPost, "/api/auth/admin/users/"+w.userID+"/impersonate", w.adminTok, nil)
	tok := asMap(t, b)["token"].(string)
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/me", tok, nil); code != http.StatusOK {
		t.Fatalf("precondition: %d", code)
	}
	if err := w.svc.SetRoles(context.Background(), w.adminID, nil); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := raw(t, w.srv, http.MethodGet, "/api/auth/me", tok, nil); code != http.StatusUnauthorized {
		t.Fatalf("an impersonation outliving its admin must be refused: %d", code)
	}
}

// Promoting a non-admin and deleting another administrator are allowed, but audited with actor and target (field names only, no values).
func TestAdminManagingAdminsIsAudited(t *testing.T) {
	w := newAdminWorld(t)
	two, err := w.svc.CreateUser(context.Background(), "two@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	updated := w.capture(EventUserUpdated)
	deleted := w.capture(EventUserDeleted)
	_ = two
	base := "/api/auth/admin/users/" + w.userID
	if code, _, _ := raw(t, w.srv, http.MethodPatch, base, w.adminTok, map[string]any{"roles": []string{"admin"}, "permissions": []string{"x"}}); code != http.StatusOK {
		t.Fatalf("promoting a non-admin: %d", code)
	}
	if len(*updated) != 1 {
		t.Fatalf("updated events: %d", len(*updated))
	}
	u := (*updated)[0].(map[string]string)
	if u["actor_id"] != w.adminID || u["target_id"] != w.userID || u["fields"] != "roles,permissions" {
		t.Fatalf("update event: %v", u)
	}
	// Demoted, the account is an ordinary user again; delete another admin.
	three, err := w.svc.CreateUser(context.Background(), "three@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	if code, _, _ := raw(t, w.srv, http.MethodDelete, "/api/auth/admin/users/"+three.ID, w.adminTok, nil); code != http.StatusOK {
		t.Fatalf("delete of another admin: %d", code)
	}
	if len(*deleted) != 1 {
		t.Fatalf("deleted events: %d", len(*deleted))
	}
	d := (*deleted)[0].(map[string]string)
	if d["actor_id"] != w.adminID || d["target_id"] != three.ID {
		t.Fatalf("delete event: %v", d)
	}
}
