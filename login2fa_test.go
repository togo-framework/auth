package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/togo-framework/togo"
	_ "modernc.org/sqlite"
)

// bootAuth starts a real kernel (in-memory SQLite) with this plugin loaded and
// returns a test server plus the auth service.
func bootAuth(t *testing.T) (*httptest.Server, *Service) {
	t.Helper()
	t.Setenv("DB_DRIVER", "sqlite")
	t.Setenv("DATABASE_URL", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	t.Setenv("AUTH_SECRET", "a-sufficiently-long-test-secret-for-login2fa!")
	t.Setenv("APP_ENV", "development")
	k := togo.New()
	t.Cleanup(func() { k.Close() })
	svc, ok := FromKernel(k)
	if !ok {
		t.Fatal("auth provider did not register")
	}
	srv := httptest.NewServer(k.Handler())
	t.Cleanup(srv.Close)
	return srv, svc
}

type client struct {
	t    *testing.T
	srv  *httptest.Server
	http *http.Client
	csrf string
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, srv: srv, http: &http.Client{Jar: jar}}
	var body map[string]string
	c.do(http.MethodGet, "/api/auth/csrf", nil, &body)
	c.csrf = body["csrf_token"]
	return c
}

func (c *client) do(method, path string, in any, out any) int {
	c.t.Helper()
	var buf bytes.Buffer
	if in != nil {
		_ = json.NewEncoder(&buf).Encode(in)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	if out != nil {
		_ = json.NewDecoder(res.Body).Decode(out)
	}
	return res.StatusCode
}

func (c *client) withBearer(token string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: c.t, srv: c.srv, http: &http.Client{Jar: jar, Transport: bearer{token}}, csrf: c.csrf}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

const pw = "correct-horse-battery-staple"

func register(t *testing.T, c *client, email string) {
	t.Helper()
	if code := c.do(http.MethodPost, "/api/auth/register", map[string]string{"email": email, "password": pw}, nil); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
}

func TestLoginWithout2FAIssuesSession(t *testing.T) {
	srv, _ := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "plain@example.com")

	var out map[string]any
	if code := c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "plain@example.com", "password": pw}, &out); code != http.StatusOK {
		t.Fatalf("login: %d", code)
	}
	if out["token"] == nil || out["mfa_required"] != nil {
		t.Fatalf("a user without 2FA should get a session directly: %v", out)
	}
}

// enable2FA enrols and verifies TOTP for the signed-in user, returning the secret.
func enable2FA(t *testing.T, c *client, email string) string {
	t.Helper()
	var login map[string]any
	c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": email, "password": pw}, &login)
	authed := c.withBearer(login["token"].(string))
	var enrol map[string]string
	if code := authed.do(http.MethodPost, "/api/auth/2fa/enroll", nil, &enrol); code != http.StatusOK {
		t.Fatalf("enroll: %d", code)
	}
	if code := authed.do(http.MethodPost, "/api/auth/2fa/verify", map[string]string{"code": totpAt(enrol["secret"], time.Now())}, nil); code != http.StatusOK {
		t.Fatalf("verify enrolment: %d", code)
	}
	return enrol["secret"]
}

func TestLoginWith2FAIsHeldForTheCode(t *testing.T) {
	srv, svc := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "guarded@example.com")
	secret := enable2FA(t, c, "guarded@example.com")

	// The password alone must no longer produce a session.
	var login map[string]any
	c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "guarded@example.com", "password": pw}, &login)
	if login["token"] != nil {
		t.Fatalf("SECURITY: a 2FA user got a session from the password alone: %v", login)
	}
	if login["mfa_required"] != true || login["challenge"] == "" {
		t.Fatalf("expected a challenge: %v", login)
	}
	challenge := login["challenge"].(string)

	// Wrong code: refused.
	if code := c.do(http.MethodPost, "/api/auth/2fa/challenge", map[string]string{"challenge": challenge, "code": "000000"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("wrong code should be 401, got %d", code)
	}
	// Right code: a session that carries the account's identity.
	var done map[string]any
	if code := c.do(http.MethodPost, "/api/auth/2fa/challenge", map[string]string{"challenge": challenge, "code": totpAt(secret, time.Now())}, &done); code != http.StatusOK {
		t.Fatalf("right code: %d", code)
	}
	id, err := svc.Verify(done["token"].(string))
	if err != nil || id.Email != "guarded@example.com" {
		t.Fatalf("session should be for the account: %v %+v", err, id)
	}
	// A challenge is single-use.
	if code := c.do(http.MethodPost, "/api/auth/2fa/challenge", map[string]string{"challenge": challenge, "code": totpAt(secret, time.Now())}, nil); code != http.StatusUnauthorized {
		t.Fatalf("a used challenge must not work again, got %d", code)
	}
}

func TestChallengeCapsBruteForce(t *testing.T) {
	srv, _ := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "brute@example.com")
	secret := enable2FA(t, c, "brute@example.com")

	var login map[string]any
	c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "brute@example.com", "password": pw}, &login)
	challenge := login["challenge"].(string)
	for i := 0; i < maxChallengeAttempts; i++ {
		c.do(http.MethodPost, "/api/auth/2fa/challenge", map[string]string{"challenge": challenge, "code": "111111"}, nil)
	}
	// Even the correct code is refused once the attempts are spent.
	if code := c.do(http.MethodPost, "/api/auth/2fa/challenge", map[string]string{"challenge": challenge, "code": totpAt(secret, time.Now())}, nil); code != http.StatusUnauthorized {
		t.Fatalf("challenge should be burned after %d wrong codes, got %d", maxChallengeAttempts, code)
	}
}

func TestChallengeRejectsTampering(t *testing.T) {
	_, svc := bootAuth(t)
	tok, _ := svc.IssueLoginChallenge("user-1")
	if _, err := svc.VerifyLoginChallenge(tok + "x"); err == nil {
		t.Fatal("a tampered challenge must be rejected")
	}
	// A session JWT is not a challenge.
	jwt, _ := svc.IssueToken(Identity{ID: "user-1"})
	if _, err := svc.VerifyLoginChallenge(jwt); err == nil {
		t.Fatal("a session token must not pass as a challenge")
	}
}

func TestReenrollCannotSilentlyDisable2FA(t *testing.T) {
	srv, svc := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "sticky@example.com")
	secret := enable2FA(t, c, "sticky@example.com")

	var login map[string]any
	c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "sticky@example.com", "password": pw}, &login)
	var done map[string]any
	c.do(http.MethodPost, "/api/auth/2fa/challenge", map[string]string{"challenge": login["challenge"].(string), "code": totpAt(secret, time.Now())}, &done)
	authed := c.withBearer(done["token"].(string))

	if code := authed.do(http.MethodPost, "/api/auth/2fa/enroll", nil, nil); code != http.StatusConflict {
		t.Fatalf("re-enrolling over active 2FA should be refused, got %d", code)
	}
	id, _ := svc.Verify(done["token"].(string))
	if !svc.SecondFactorRequired(context.Background(), id.ID) {
		t.Fatal("2FA must still be on")
	}
	if code := authed.do(http.MethodPost, "/api/auth/2fa/disable", map[string]string{"code": "000000"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("disabling needs a valid code, got %d", code)
	}
	if code := authed.do(http.MethodPost, "/api/auth/2fa/disable", map[string]string{"code": totpAt(secret, time.Now())}, nil); code != http.StatusOK {
		t.Fatalf("disable with a valid code: %d", code)
	}
}

func TestRegisteredSecondFactorGatesLogin(t *testing.T) {
	srv, _ := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "external@example.com")
	RegisterSecondFactor(func(_ context.Context, _ string) bool { return true })
	t.Cleanup(func() {
		secondFactorsMu.Lock()
		secondFactors = nil
		secondFactorsMu.Unlock()
	})

	var login map[string]any
	c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "external@example.com", "password": pw}, &login)
	if login["token"] != nil || login["mfa_required"] != true {
		t.Fatalf("a registered second factor must gate login: %v", login)
	}
}

func TestPasswordReset(t *testing.T) {
	srv, svc := bootAuth(t)
	c := newClient(t, srv)
	register(t, c, "forgetful@example.com")

	var captured map[string]string
	svc.k.Hooks.On(EventPasswordResetRequested, 50, func(_ context.Context, payload any) error {
		captured = payload.(map[string]string)
		return nil
	})

	var res map[string]string
	if code := c.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"email": "forgetful@example.com"}, &res); code != http.StatusAccepted {
		t.Fatalf("forgot: %d", code)
	}
	if strings.Contains(strings.ToLower(res["status"]), "token") || res["token"] != "" {
		t.Fatalf("SECURITY: the reset token must never be in the response: %v", res)
	}
	if captured == nil || captured["token"] == "" {
		t.Fatal("the token should be delivered through the event")
	}

	// Unknown email: identical response, no event.
	captured = nil
	var unknown map[string]string
	code := c.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"email": "nobody@example.com"}, &unknown)
	if code != http.StatusAccepted || unknown["status"] != res["status"] || captured != nil {
		t.Fatalf("an unknown email must be indistinguishable: %d %v %v", code, unknown, captured)
	}

	// Reset with the delivered token, then sign in with the new password.
	c.do(http.MethodPost, "/api/auth/password/forgot", map[string]string{"email": "forgetful@example.com"}, nil)
	token := captured["token"]
	newPW := "a-completely-new-passphrase"
	if code := c.do(http.MethodPost, "/api/auth/password/reset", map[string]string{"token": token, "password": newPW}, nil); code != http.StatusOK {
		t.Fatalf("reset: %d", code)
	}
	var login map[string]any
	if code := c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "forgetful@example.com", "password": newPW}, &login); code != http.StatusOK || login["token"] == nil {
		t.Fatalf("login with the new password: %d %v", code, login)
	}
	if code := c.do(http.MethodPost, "/api/auth/login", map[string]string{"email": "forgetful@example.com", "password": pw}, nil); code != http.StatusUnauthorized {
		t.Fatalf("the old password must stop working, got %d", code)
	}
	// Single-use.
	if code := c.do(http.MethodPost, "/api/auth/password/reset", map[string]string{"token": token, "password": "yet-another-passphrase"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("a used reset token must be refused, got %d", code)
	}
	if code := c.do(http.MethodPost, "/api/auth/password/reset", map[string]string{"token": "guessed", "password": "yet-another-passphrase"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("an unknown token must be refused, got %d", code)
	}
}
