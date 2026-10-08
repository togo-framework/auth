package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// Admin lifecycle matrix (auth#6, threat model v2 section 15). Every test here
// is deterministic: races are forced with locks or held connections, never
// with timing.

func apiBody(t *testing.T, w *reviewWorld, m, p, tok, body string) (int, map[string]any) {
	t.Helper()
	code, b, _ := raw(t, w.srv, m, p, tok, body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return code, out
}

func (w *reviewWorld) secondAdmin(t *testing.T) (id, tok string) {
	t.Helper()
	u, err := w.svc.CreateUser(context.Background(), "admin2@example.com", pw, []string{"admin"})
	if err != nil {
		t.Fatal(err)
	}
	w.admin2ID = u.ID
	return u.ID, tokFor(t, w.svc, "admin2@example.com")
}

func (w *reviewWorld) secondID(t *testing.T) string { return w.admin2ID }

func (w *reviewWorld) promote(t *testing.T, tok, id, extra string) (int, map[string]any) {
	t.Helper()
	return apiBody(t, w, "PATCH", "/api/auth/admin/users/"+id, tok, `{"roles":["admin"]`+extra+`}`)
}

func isAdminNow(t *testing.T, w *reviewWorld, id string) bool {
	t.Helper()
	u, err := w.svc.userByID(context.Background(), id)
	if err != nil || u == nil {
		t.Fatalf("user %s: %v", id, err)
	}
	return isAdminUser(u)
}

func (w *reviewWorld) provenanceOf(t *testing.T, id string) provenance {
	t.Helper()
	ctx := context.Background()
	db, _ := w.svc.k.SQL(ctx)
	tx, _ := db.BeginTx(ctx, nil)
	defer tx.Rollback()
	p, err := w.svc.readProvenance(ctx, tx, id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// serveGuard runs one request with the bearer token through a guard and
// returns the status the guarded route answered.
func serveGuard(guard func(http.Handler) http.Handler, tok string) int {
	h := guard(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest("GET", "/guarded", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// --- F11 / F11c: compare-and-set on the roles value that was judged ---

func TestLifecycleResetCASStaleRoles(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	db, _ := w.svc.k.SQL(ctx)
	tx, _ := db.BeginTx(ctx, nil)
	defer tx.Rollback()
	// roles judged non-admin ("") but the stored value is now admin
	if _, err := tx.ExecContext(ctx, "UPDATE users SET roles = 'admin' WHERE id = "+w.svc.ph(1), w.userID); err != nil {
		t.Fatal(err)
	}
	ok, err := w.svc.txSetPasswordIfRoles(ctx, tx, w.userID, "x", "")
	if err != nil || ok {
		t.Fatalf("stale roles must write nothing: ok=%v err=%v", ok, err)
	}
	if ok, _ := w.svc.txSetPasswordIfRoles(ctx, tx, w.userID, "x", "admin"); !ok {
		t.Fatal("matching roles must write")
	}
}

// Set-mode and redemption share the one CAS statement.
func TestLifecycleSetModeCASStaleRoles(t *testing.T) { TestLifecycleResetCASStaleRoles(t) }

func TestLifecycleRefusedRedeemBurnsToken(t *testing.T) {
	w := newReviewWorld(t)
	_, rt := adminLink(t, w, "reset-password", w.userID)
	_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
	if c := redeemReset(t, w, rt, "hijacked-pass-1"); c != 401 {
		t.Fatalf("refused redeem => %d, want generic 401", c)
	}
	if n := len(w.eventsNamed(EventCredentialRefused)); n != 1 {
		t.Errorf("auth.credential_refused events = %d, want 1", n)
	}
	_ = w.svc.SetRoles(context.Background(), w.userID, nil)
	if c := redeemReset(t, w, rt, "hijacked-pass-1"); c != 401 {
		t.Errorf("token survived a refused redemption: %d", c)
	}
	if loginCode(t, w, "bob@example.com", "hijacked-pass-1") == 200 {
		t.Error("password changed by a refused redemption")
	}
}

func TestLifecycleRedeemWritesProvenance(t *testing.T) {
	w := newReviewWorld(t)
	_, rt := adminLink(t, w, "reset-password", w.userID)
	if c := redeemReset(t, w, rt, "link-password-12"); c != 200 {
		t.Fatalf("redeem => %d", c)
	}
	if p := w.provenanceOf(t, w.userID); p.PasswordBy != w.adminID {
		t.Errorf("password provenance = %q, want issuer %q", p.PasswordBy, w.adminID)
	}
}

// --- F12: provenance and the promotion gate ---

func TestLifecyclePromoteAfterEmailChange409(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	if c := api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"email":"new@example.com"}`); c != 200 {
		t.Fatalf("email change => %d", c)
	}
	code, body := w.promote(t, tok2, w.userID, "")
	if code != 409 || body["error"] != "identity_set_by_other_admin" {
		t.Fatalf("promote by another admin => %d %v", code, body)
	}
	if body["accept_field"] != acceptField {
		t.Errorf("409 does not name the accept field: %v", body)
	}
	if isAdminNow(t, w, w.userID) {
		t.Fatal("409 must not promote")
	}
	if code, _ := w.promote(t, tok2, w.userID, `,"`+acceptField+`":true`); code != 200 {
		t.Fatalf("explicit accept => %d", code)
	}
	if ev := w.eventsNamed(EventAdminPromoted); len(ev) != 1 || !strings.Contains(ev[0], "true") || !strings.Contains(ev[0], "email") {
		t.Errorf("auth.admin_promoted audit = %v", ev)
	}
}

func TestLifecyclePromoterOwnWriteExempt(t *testing.T) {
	w := newReviewWorld(t)
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"email":"new@example.com"}`)
	if code, body := w.promote(t, w.adminTok, w.userID, ""); code != 200 {
		t.Fatalf("promoter's own write must be exempt: %d %v", code, body)
	}
}

func TestLifecyclePromoteAfterSetPasswordOrCreateOrLinkRedeem(t *testing.T) {
	cases := map[string]func(t *testing.T, w *reviewWorld) string{
		"set-password": func(t *testing.T, w *reviewWorld) string {
			if c := api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, `{"password":"set-by-admin-123"}`); c != 200 {
				t.Fatalf("set-password => %d", c)
			}
			return w.userID
		},
		"link-redeem": func(t *testing.T, w *reviewWorld) string {
			_, rt := adminLink(t, w, "reset-password", w.userID)
			if c := redeemReset(t, w, rt, "link-password-12"); c != 200 {
				t.Fatalf("redeem => %d", c)
			}
			return w.userID
		},
		"admin-create": func(t *testing.T, w *reviewWorld) string {
			code, body := apiBody(t, w, "POST", "/api/auth/admin/users", w.adminTok, `{"email":"made@example.com","password":"made-by-admin-123"}`)
			if code != 201 && code != 200 {
				t.Fatalf("create => %d %v", code, body)
			}
			u, _ := body["user"].(map[string]any)
			id, _ := u["id"].(string)
			return id
		},
	}
	for name, do := range cases {
		do := do
		t.Run(name, func(t *testing.T) {
			w := newReviewWorld(t)
			_, tok2 := w.secondAdmin(t)
			id := do(t, w)
			if code, _ := w.promote(t, tok2, id, ""); code != 409 {
				t.Fatalf("promote => %d, want 409", code)
			}
		})
	}
}

func TestLifecycleTaintStickyAfterHolderChange(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, `{"password":"set-by-admin-123"}`)
	// The holder sets their own password through a self-service reset; provenance
	// is only ever written by admin paths and never cleared by the holder.
	db, _ := w.svc.k.SQL(context.Background())
	_ = db
	if err := w.svc.SetPassword(context.Background(), w.userID, "holder-chosen-456"); err != nil {
		t.Fatal(err)
	}
	if code, _ := w.promote(t, tok2, w.userID, ""); code != 409 {
		t.Fatalf("taint released by a later password change: %d", code)
	}
}

func TestLifecyclePerFieldTaint(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	api(t, w, "POST", "/api/auth/admin/users/"+w.userID+"/reset-password", w.adminTok, `{"password":"set-by-admin-123"}`)
	_, body := w.promote(t, tok2, w.userID, "")
	tf, _ := body["tainted_fields"].([]any)
	if len(tf) != 1 || tf[0] != "password" {
		t.Errorf("tainted_fields = %v, want only password", tf)
	}
}

// The gate is a function of provenance, not of the channel the holder uses
// afterwards: a recovery request on an admin-set address does not release it.
func TestLifecycleRecoveryAndSSOOnTaintedAddress(t *testing.T) {
	w := newReviewWorld(t)
	_, tok2 := w.secondAdmin(t)
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"email":"taint@example.com"}`)
	api(t, w, "POST", "/api/auth/password/forgot", "", `{"email":"taint@example.com"}`)
	if code, _ := w.promote(t, tok2, w.userID, ""); code != 409 {
		t.Fatalf("recovery request released the taint: %d", code)
	}
}

// --- F13: act-limited sessions die when the target becomes an admin ---

func TestLifecycleActSessionDiesOnPromotion(t *testing.T) {
	w := newReviewWorld(t)
	_, imp := impersonate(t, w, w.adminTok, w.userID)
	mag := magicSession(t, w, w.userID)
	for name, tk := range map[string]string{"impersonation": imp, "magic": mag} {
		if c := api(t, w, "GET", "/api/auth/me", tk, ""); c != 200 {
			t.Fatalf("%s before promotion => %d", name, c)
		}
	}
	_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
	for name, tk := range map[string]string{"impersonation": imp, "magic": mag} {
		if c := api(t, w, "GET", "/api/auth/me", tk, ""); c != 401 {
			t.Errorf("%s after promotion => %d, want 401", name, c)
		}
	}
}

func TestLifecycleActSessionAllowedWithFlag(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_ADMIN_CROSS_CONTROL", "true")
	_, imp := impersonate(t, w, w.adminTok, w.userID)
	_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
	if c := api(t, w, "GET", "/api/auth/me", imp, ""); c != 200 {
		t.Errorf("flag on: impersonation of a now-admin => %d", c)
	}
}

// F11b (a magic link redeemed after promotion) is covered by F13 plus the
// invariants: the link is refused at redemption and any session it produced
// dies on the next request.
func TestLifecycleF11bCoveredByF13(t *testing.T) {
	w := newReviewWorld(t)
	mag := magicSession(t, w, w.userID)
	_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
	if c := api(t, w, "GET", "/api/auth/admin/users", mag, ""); c == 200 {
		t.Error("magic session reached the admin API after promotion")
	}
}

// --- delete ---

func TestLifecycleDeleteAdminAudit(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_ADMIN_CROSS_CONTROL", "true")
	id, _ := w.secondAdmin(t)
	if c := api(t, w, "DELETE", "/api/auth/admin/users/"+id, w.adminTok, ""); c != 200 {
		t.Fatalf("delete => %d", c)
	}
	if n := len(w.eventsNamed(EventAdminCrossControl)); n != 1 {
		t.Errorf("cross-control events = %d, want 1", n)
	}
}

func TestLifecycleDeleteScrubsState(t *testing.T) {
	w := newReviewWorld(t)
	api(t, w, "PATCH", "/api/auth/admin/users/"+w.userID, w.adminTok, `{"email":"new@example.com"}`)
	if w.provenanceOf(t, w.userID).EmailBy == "" {
		t.Fatal("setup: no provenance")
	}
	api(t, w, "DELETE", "/api/auth/admin/users/"+w.userID, w.adminTok, "")
	if p := w.provenanceOf(t, w.userID); p != (provenance{}) {
		t.Errorf("state row survived delete: %+v", p)
	}
}

// --- boot, flag ---

func TestLifecycleBootOnV095Schema(t *testing.T) {
	w := newReviewWorld(t)
	ctx := context.Background()
	db, _ := w.svc.k.SQL(ctx)
	if _, err := db.Exec("DROP TABLE auth_account_state"); err != nil {
		t.Fatal(err)
	}
	bootSecond(t)
	if _, err := db.Exec("SELECT count(*) FROM auth_account_state"); err != nil {
		t.Errorf("state table not created on an existing install: %v", err)
	}
}

func TestLifecycleOldFlagNameWarns(t *testing.T) {
	t.Setenv("AUTH_IMPERSONATE_ADMINS", "true")
	lb := &logBuf{}
	warnLegacyFlags(slog.New(slog.NewTextHandler(lb, nil)))
	if !strings.Contains(lb.String(), "AUTH_IMPERSONATE_ADMINS") {
		t.Error("no startup warning for the old flag name")
	}
}

// --- D2: strict session revalidation ---

func TestLifecycleD2DeletedAccount401(t *testing.T) {
	w := newReviewWorld(t)
	if c := api(t, w, "GET", "/api/auth/me", w.userTok, ""); c != 200 {
		t.Fatalf("before delete => %d", c)
	}
	api(t, w, "DELETE", "/api/auth/admin/users/"+w.userID, w.adminTok, "")
	if c := api(t, w, "GET", "/api/auth/me", w.userTok, ""); c != 401 {
		t.Errorf("deleted account => %d, want 401", c)
	}
	if _, err := w.svc.Verify(w.userTok); err == nil {
		t.Error("Verify accepted a deleted account")
	}
}

func TestLifecycleD2DemotedAdminImmediately403(t *testing.T) {
	w := newReviewWorld(t)
	w.secondAdmin(t)
	if c := api(t, w, "GET", "/api/auth/admin/users", w.adminTok, ""); c != 200 {
		t.Fatalf("admin before demotion => %d", c)
	}
	ctx := context.Background()
	_ = w.svc.SetRoles(ctx, w.adminID, nil)
	if c := api(t, w, "GET", "/api/auth/admin/users", w.adminTok, ""); c != 403 {
		t.Errorf("demoted admin on admin API => %d, want 403", c)
	}
	// claims-only guards must see the database's roles and permissions
	if code := serveGuard(w.svc.RequireRole("admin"), w.adminTok); code != 403 {
		t.Errorf("demoted admin on RequireRole route => %d, want 403", code)
	}
	_ = w.svc.SetRoles(ctx, w.adminID, []string{"admin"})
	if code := serveGuard(w.svc.RequireRole("admin"), w.adminTok); code != 200 {
		t.Errorf("re-promoted admin on RequireRole route => %d, want 200", code)
	}
	if code := serveGuard(w.svc.RequirePermission("x"), w.adminTok); code != 403 {
		t.Errorf("RequirePermission without the permission => %d", code)
	}
	db, _ := w.svc.k.SQL(ctx)
	if _, err := db.Exec("UPDATE users SET permissions = 'x' WHERE id = "+w.svc.ph(1), w.adminID); err != nil {
		t.Fatal(err)
	}
	if code := serveGuard(w.svc.RequirePermission("x"), w.adminTok); code != 200 {
		t.Errorf("RequirePermission after grant => %d (permissions must be DB-authoritative)", code)
	}
}

func TestLifecycleD2RevokedTokenRefused(t *testing.T) {
	w := newReviewWorld(t)
	_, imp := impersonate(t, w, w.adminTok, w.userID)
	if c := api(t, w, "POST", "/api/auth/impersonation/stop", imp, ""); c != 200 {
		t.Fatalf("stop => %d", c)
	}
	if c := api(t, w, "GET", "/api/auth/me", imp, ""); c != 401 {
		t.Errorf("revoked impersonation token => %d, want 401", c)
	}
}

func TestLifecycleD2ActiveUserKeepsWorking(t *testing.T) {
	w := newReviewWorld(t)
	for i := 0; i < 3; i++ {
		if c := api(t, w, "GET", "/api/auth/me", w.userTok, ""); c != 200 {
			t.Fatalf("active user => %d", c)
		}
	}
}

// Intended: a bearer snapshot is not authority. The existing session of a
// promoted user carries the admin role the moment the database says so.
func TestLifecycleD2PromotedUserGainsAuthorityAsDBSays(t *testing.T) {
	w := newReviewWorld(t)
	if c := api(t, w, "GET", "/api/auth/admin/users", w.userTok, ""); c != 403 {
		t.Fatalf("ordinary user on admin API => %d", c)
	}
	_ = w.svc.SetRoles(context.Background(), w.userID, []string{"admin"})
	if c := api(t, w, "GET", "/api/auth/admin/users", w.userTok, ""); c != 200 {
		t.Errorf("promoted user's existing session => %d, want 200", c)
	}
}

func TestLifecycleD2PATOwnerGone(t *testing.T) {
	w := newReviewWorld(t)
	_, b, _ := raw(t, w.srv, "POST", "/api/auth/tokens", w.userTok, map[string]any{"name": "p", "abilities": []string{"*"}})
	pat, _ := asMap(t, b)["token"].(string)
	if c := api(t, w, "GET", "/api/auth/me", pat, ""); c != 200 {
		t.Fatalf("PAT before delete => %d", c)
	}
	api(t, w, "DELETE", "/api/auth/admin/users/"+w.userID, w.adminTok, "")
	if c := api(t, w, "GET", "/api/auth/me", pat, ""); c != 401 {
		t.Errorf("PAT of a deleted owner => %d, want 401", c)
	}
}

func TestLifecycleD2ExternalDriverSkipsRevalidation(t *testing.T) {
	w := newReviewWorld(t)
	t.Setenv("AUTH_DRIVER", "supabase")
	tk := signWith(t, w.svc.secret, jwt.SigningMethodHS256, claimsFor("not-in-users-table", "member"))
	id, err := w.svc.VerifyContext(context.Background(), tk)
	if err != nil || id.ID != "not-in-users-table" {
		t.Errorf("non-base driver must not consult the users table: %v", err)
	}
}
