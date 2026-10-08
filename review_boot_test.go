package auth

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/togo-framework/togo"
)

// Security review harness (auth#6).
//
// By default the review tests run on in-memory SQLite like the rest of the
// suite. To run the same tests on PostgreSQL, build with `-tags authpg` and set
// AUTH_REVIEW_PG_URL to a scratch database (it is emptied of auth tables at the
// start of every test):
//
//	AUTH_REVIEW_PG_URL=postgres://user:pass@localhost:55450/scratch go test -tags authpg ./...

var pgDriverLinked bool // set by review_pg_test.go (build tag authpg)

var authTables = []string{
	"auth_magic_links", "auth_revoked_tokens", "auth_password_resets", "personal_access_tokens",
	"auth_totp", "auth_pins", "otp_codes", "auth_sessions", "auth_account_state", "auth_reset_issuers", "auth_recovery_context", "auth_priv_epoch", "auth_admin_guard", "users",
}

func usingPG() bool { return os.Getenv("AUTH_REVIEW_PG_URL") != "" && pgDriverLinked }

// logBuf is a goroutine-safe log sink.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func resetPG(t *testing.T) {
	t.Helper()
	db, err := sql.Open("pgx", os.Getenv("AUTH_REVIEW_PG_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, tb := range authTables {
		if _, err := db.Exec("DROP TABLE IF EXISTS " + tb + " CASCADE"); err != nil {
			t.Fatal(err)
		}
	}
}

func setReviewEnv(t *testing.T) {
	t.Helper()
	if usingPG() {
		t.Setenv("DB_DRIVER", "pgx")
		t.Setenv("DATABASE_URL", os.Getenv("AUTH_REVIEW_PG_URL"))
	} else {
		t.Setenv("DB_DRIVER", "sqlite")
		t.Setenv("DATABASE_URL", "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared")
	}
	t.Setenv("AUTH_SECRET", "a-sufficiently-long-test-secret-for-login2fa!")
	t.Setenv("APP_ENV", "development")
}

// bootReview boots a real kernel, captures its log, and returns the server.
func bootReview(t *testing.T) (*httptest.Server, *Service, *logBuf) {
	t.Helper()
	setReviewEnv(t)
	if usingPG() {
		resetPG(t)
	}
	k := togo.New()
	t.Cleanup(func() { k.Close() })
	lb := &logBuf{}
	k.Log = slog.New(slog.NewTextHandler(lb, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc, ok := FromKernel(k)
	if !ok {
		t.Fatal("auth provider did not register")
	}
	srv := httptest.NewServer(k.Handler())
	t.Cleanup(srv.Close)
	return srv, svc, lb
}

// bootSecond boots a second, independent kernel (a second app instance) on the
// same database, to test invariants that an in-process mutex cannot protect.
func bootSecond(t *testing.T) (*httptest.Server, *Service) {
	t.Helper()
	k := togo.New()
	t.Cleanup(func() { k.Close() })
	svc, _ := FromKernel(k)
	srv := httptest.NewServer(k.Handler())
	t.Cleanup(srv.Close)
	return srv, svc
}

type reviewWorld struct {
	*adminWorld
	userExtra string // token of the second administrator, when a test created one
	admin2ID  string
	log       *logBuf
	// every auth event payload, stringified, in order
	mu     sync.Mutex
	events []string
}

var allEvents = []string{
	EventRegistered, EventLogin, EventLoginFailed, EventLogout, EventPasswordChanged,
	EventPasswordResetRequested, EventPasswordReset, EventLoginChallenged,
	EventUserCreated, EventUserUpdated, EventUserDeleted, EventUserImpersonated,
	EventImpersonationEnded, EventMagicLinkIssued, EventAdminResetLinkIssued, EventAdminCrossControl,
	EventAdminPromoted, EventAdminDemoted, EventCredentialRefused,
}

func newReviewWorld(t *testing.T) *reviewWorld {
	t.Helper()
	srv, svc, lb := bootReview(t)
	ctx := context.Background()
	admin, err := svc.CreateUser(ctx, "root@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := svc.CreateUser(ctx, "bob@example.com", pw, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := &reviewWorld{adminWorld: &adminWorld{
		srv: srv, svc: svc,
		adminID: admin.ID, adminTok: loginToken(t, srv, "root@example.com"),
		userID: user.ID, userTok: loginToken(t, srv, "bob@example.com"),
		adminMail: "root@example.com",
	}, log: lb}
	for _, ev := range allEvents {
		ev := ev
		svc.k.Hooks.On(ev, 1, func(_ context.Context, p any) error {
			w.mu.Lock()
			w.events = append(w.events, ev+" "+fmtAny(p))
			w.mu.Unlock()
			return nil
		})
	}
	return w
}

func (w *reviewWorld) eventDump() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return strings.Join(w.events, "\n")
}
func (w *reviewWorld) eventsNamed(n string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, e := range w.events {
		if strings.HasPrefix(e, n+" ") {
			out = append(out, e)
		}
	}
	return out
}

func fmtAny(p any) string { return fmt.Sprintf("%+v", p) }

// tokFor mints a login-equivalent token without going through the rate-limited
// login endpoint.
func tokFor(t *testing.T, s *Service, email string) string {
	t.Helper()
	u, err := s.userByEmail(context.Background(), email)
	if err != nil || u == nil {
		t.Fatalf("no user %s: %v", email, err)
	}
	tok, err := s.IssueToken(*u.identity(s.def))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// rawFrom is raw with a distinct client address (via X-Forwarded-For from the
// trusted loopback proxy), so the per-IP rate limiter does not mask races.
func rawFrom(t *testing.T, srv *httptest.Server, ip, method, path, token, body string) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Error(err)
		return 0, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", ip)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		t.Error(err)
		return 0, nil
	}
	res.Body.Close()
	return res.StatusCode, res.Header
}
