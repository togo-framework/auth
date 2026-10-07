package auth

import (
	"context"
	"database/sql"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Magic and admin-issued reset links.
//
// A link carries a random 256-bit token. Only its SHA-256 hash is stored, the
// raw token exists in exactly one place (the administrator's HTTP response) and
// never in an event, a log line or the database. Each token is single-use
// (consumed with a conditional UPDATE, so two concurrent requests cannot both
// win), short-lived, bound to one purpose by the table that holds it, and
// retired when a newer link is issued for the same account.
//
//	magic  -> auth_magic_links,    consumed by GET /api/auth/magic?token=
//	reset  -> auth_password_resets, consumed by POST /api/auth/password/reset
//
// The base URL comes only from configuration (AUTH_PUBLIC_URL, else APP_URL).
// When neither is a valid http(s) URL the link is a relative path: the Host
// header is never trusted, so a forged one cannot redirect a link to an
// attacker's site.

// MagicLinkTTL is how long an admin-issued magic link stays valid.
const MagicLinkTTL = 15 * time.Minute

func (s *Service) ensureAdminSchema(ctx context.Context) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS auth_magic_links (
			token_hash text PRIMARY KEY,
			user_id text NOT NULL,
			created_by text NOT NULL DEFAULT '',
			expires_at text NOT NULL,
			used text NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS auth_revoked_tokens (
			jti text PRIMARY KEY,
			expires_at text NOT NULL
		)`,
		// Which administrator issued an admin-issued reset token; self-service
		// (forgot-password) tokens have no row here.
		`CREATE TABLE IF NOT EXISTS auth_reset_issuers (token_hash text PRIMARY KEY, created_by text NOT NULL)`,
		// One sentinel row, locked by every admin mutation (see adminTx).
		`CREATE TABLE IF NOT EXISTS auth_admin_guard (id integer PRIMARY KEY, n integer NOT NULL DEFAULT 0)`,
		`INSERT INTO auth_admin_guard (id, n) VALUES (1, 0) ON CONFLICT (id) DO NOTHING`,
		// Who set an account's email and password when it was not the holder (see
		// admin_state.go). A side table: users is host-owned and never altered.
		ensureAccountStateSQL(),
	}
	stmts = append(stmts, ensureRecoveryContextSQL()...)
	for _, q := range stmts {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// publicBase returns the configured public base URL without a trailing slash,
// or "" when none is set or the value is not an absolute http(s) URL.
func publicBase() string {
	v := strings.TrimRight(strings.TrimSpace(firstEnv("AUTH_PUBLIC_URL", "APP_URL")), "/")
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return v
}

func magicLink(token string) string {
	return publicBase() + "/api/auth/magic?token=" + url.QueryEscape(token)
}

// resetLink points at the frontend's reset page (AUTH_RESET_PATH, default
// /reset-password), which posts the token to /api/auth/password/reset.
func resetLink(token string) string {
	path := firstEnv("AUTH_RESET_PATH")
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		path = "/reset-password"
	}
	return publicBase() + path + "?token=" + url.QueryEscape(token)
}

func postLoginURL() string {
	if v := firstEnv("AUTH_POST_LOGIN_URL", "DASHBOARD_URL", "APP_URL"); v != "" {
		return v
	}
	return "/"
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// issueLinkToken stores a fresh token for userID in table, retiring the
// account's earlier unused ones, in one transaction.
func (s *Service) issueLinkToken(ctx context.Context, table, createdBy, userID string, ttl time.Duration) (string, time.Time, error) {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return "", time.Time{}, err
	}
	token := randomToken()
	now := time.Now()
	exp := now.Add(ttl).UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	//#nosec G202 -- table is a constant chosen by the caller; values parameterized
	if _, err := tx.ExecContext(ctx, "UPDATE "+table+" SET used = 'superseded' WHERE user_id = "+s.ph(1)+" AND used = ''", userID); err != nil {
		return "", time.Time{}, err
	}
	// Expired rows are dead weight; sweep them as we go.
	//#nosec G202 -- table is a constant chosen by the caller; values parameterized
	if _, err := tx.ExecContext(ctx, "DELETE FROM "+table+" WHERE expires_at < "+s.ph(1), stamp(now.Add(-24*time.Hour))); err != nil {
		return "", time.Time{}, err
	}
	var ins string
	args := []any{sha256hex(token), userID}
	if table == "auth_magic_links" {
		ins = "INSERT INTO auth_magic_links (token_hash, user_id, created_by, expires_at, used) VALUES (" + s.ph(1) + ", " + s.ph(2) + ", " + s.ph(3) + ", " + s.ph(4) + ", '')"
		args = append(args, createdBy, stamp(exp))
	} else {
		ins = "INSERT INTO auth_password_resets (token_hash, user_id, expires_at, used) VALUES (" + s.ph(1) + ", " + s.ph(2) + ", " + s.ph(3) + ", '')"
		args = append(args, stamp(exp))
		if createdBy != "" {
			//#nosec G202 -- dialect placeholders only; values parameterized
			if _, err := tx.ExecContext(ctx, "INSERT INTO auth_reset_issuers (token_hash, created_by) VALUES ("+s.ph(1)+", "+s.ph(2)+")", sha256hex(token), createdBy); err != nil {
				return "", time.Time{}, err
			}
		}
	}
	//#nosec G202 -- constant statements; dialect placeholders only
	if _, err := tx.ExecContext(ctx, ins, args...); err != nil {
		return "", time.Time{}, err
	}
	// The context the token is issued against; redemption re-checks it.
	if err := s.recordRecoveryContext(ctx, tx, sha256hex(token), userID); err != nil {
		return "", time.Time{}, err
	}
	// Context rows of tokens long gone are dead weight.
	//#nosec G202 -- dialect placeholder only; value parameterized
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_recovery_context WHERE issued_at < "+s.ph(1), stamp(now.Add(-24*time.Hour))); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return token, exp, nil
}

func (s *Service) createMagicToken(ctx context.Context, userID, createdBy string) (string, time.Time, error) {
	return s.issueLinkToken(ctx, "auth_magic_links", createdBy, userID, MagicLinkTTL)
}

func (s *Service) createAdminResetToken(ctx context.Context, userID, createdBy string) (string, time.Time, error) {
	return s.issueLinkToken(ctx, "auth_password_resets", createdBy, userID, PasswordResetTTL)
}

// handleMagicConsume redeems a magic link: it burns the token, starts a session
// for the account and redirects to the post-login URL. Every failure is the
// same 401 so the endpoint reveals nothing about which tokens exist.
//
// A link does not bypass a second factor: an account with 2FA must sign in
// normally.
func (s *Service) handleMagicConsume(w http.ResponseWriter, r *http.Request) {
	invalid := func() { writeErr(w, http.StatusUnauthorized, "link invalid or expired") }
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" || len(token) > 256 {
		invalid()
		return
	}
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		s.adminInternal(w, "magic link", err)
		return
	}
	hash := sha256hex(token)
	var userID, expiresAt, used, issuer string
	//#nosec G202 -- dialect placeholder only; value parameterized
	switch err := db.QueryRowContext(ctx, "SELECT user_id, expires_at, used, created_by FROM auth_magic_links WHERE token_hash = "+s.ph(1), hash).Scan(&userID, &expiresAt, &used, &issuer); err {
	case nil:
	case sql.ErrNoRows:
		invalid()
		return
	default:
		s.adminInternal(w, "magic link", err)
		return
	}
	if exp, err := time.Parse(time.RFC3339, expiresAt); err != nil || time.Now().After(exp) || used != "" {
		invalid()
		return
	}
	// The conditional update is the single-use gate: exactly one caller sees
	// one affected row.
	//#nosec G202 -- dialect placeholders only; values parameterized
	res, err := db.ExecContext(ctx, "UPDATE auth_magic_links SET used = "+s.ph(1)+" WHERE token_hash = "+s.ph(2)+" AND used = ''", stamp(time.Now()), hash)
	if err != nil {
		s.adminInternal(w, "magic link", err)
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		invalid()
		return
	}
	u, err := s.userByID(ctx, userID)
	if err != nil {
		s.adminInternal(w, "magic link", err)
		return
	}
	if u == nil {
		invalid()
		return
	}
	// The link was issued against the account as it was then: a promotion (or a
	// promote-demote round trip) since voids it. The token is burned already.
	if ok, err := s.linkContextHolds(ctx, hash, u.ID); err != nil {
		s.adminInternal(w, "magic link", err)
		return
	} else if !ok {
		invalid()
		return
	}
	if s.SecondFactorRequired(ctx, u.ID) {
		writeErr(w, http.StatusForbidden, "second factor required; sign in with your password")
		return
	}
	// A link an admin issued for an ordinary user must not outlive that user
	// becoming an administrator (no admin-to-admin takeover by default).
	if issuer != "" && isAdminUser(u) && !crossControlAllowed() {
		invalid()
		return
	}
	id := *u.identity(s.def)
	// The session names the administrator who issued the link (act claim,
	// /me `impersonator`, login event) and lasts only as long as an
	// impersonation would, so a link is never an anonymous way in.
	id.Impersonator = issuer
	ttl := s.ttl
	if issuer != "" {
		if err := s.checkImpersonation(ctx, &id); err != nil {
			invalid() // the issuing admin is no longer an administrator
			return
		}
		ttl = impersonationTTL()
	}
	session, err := s.signToken(id, ttl)
	if err != nil {
		s.adminInternal(w, "magic link session", err)
		return
	}
	s.startSession(w, ctx, session)
	s.fire(ctx, EventLogin, id)
	if issuer != "" {
		s.fire(ctx, EventMagicLinkRedeemed, map[string]string{"actor_id": issuer, "target_id": u.ID, "at": stamp(time.Now())})
	}
	http.Redirect(w, r, postLoginURL(), http.StatusFound)
}

// linkContextHolds re-checks a magic link's issuance context under the account
// row lock (see admin_recovery.go). The email is not part of a magic link's
// meaning, so only the administrator status and privilege epoch are compared.
func (s *Service) linkContextHolds(ctx context.Context, tokenHash, userID string) (bool, error) {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return false, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	if found, err := s.txLockUser(ctx, tx, userID); err != nil || !found {
		return false, err
	}
	u, err := s.txUser(ctx, tx, userID)
	if err != nil || u == nil {
		return false, err
	}
	ok, err := s.recoveryContextHolds(ctx, tx, tokenHash, u, false)
	if err != nil {
		return false, err
	}
	return ok, tx.Commit()
}
