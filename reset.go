package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Password reset (new in v0.9.0). The flow:
//
//	POST /api/auth/password/forgot {email}
//	  → always 202, whether or not the email has an account, so the endpoint
//	    cannot be used to discover accounts. If it does, a single-use token is
//	    created and EventPasswordResetRequested fires with the plaintext token;
//	    a mail/SMS/notifications listener delivers the link. Only its SHA-256
//	    hash is stored.
//	POST /api/auth/password/reset {token, password}
//	  → sets the new password, burns the token (and any other outstanding ones
//	    for that user), fires EventPasswordReset.

// PasswordResetTTL is how long a reset link stays valid.
const PasswordResetTTL = 30 * time.Minute

func (s *Service) ensureResetSchema(ctx context.Context) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_password_resets (
		token_hash text PRIMARY KEY,
		user_id text NOT NULL,
		expires_at text NOT NULL,
		used text NOT NULL DEFAULT ''
	)`)
	return err
}

func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Service) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || strings.TrimSpace(body.Email) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	// Same response either way; the work happens only for a real account.
	defer writeJSON(w, http.StatusAccepted, map[string]string{"status": "if that account exists, a reset link has been sent"})

	ctx := r.Context()
	user, err := s.userByEmail(ctx, body.Email)
	if err != nil || user == nil {
		return
	}
	db, err := s.k.SQL(ctx)
	if err != nil {
		return
	}
	token := randomToken() + randomToken()
	expires := time.Now().Add(PasswordResetTTL).UTC()
	// The token and the context it is issued against (email, who set it,
	// administrator status) are stored together; redemption re-checks them.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer func() { _ = tx.Rollback() }()
	//#nosec G202 -- dialect placeholders only; values parameterized
	if _, err := tx.ExecContext(ctx,
		"INSERT INTO auth_password_resets (token_hash, user_id, expires_at, used) VALUES ("+s.ph(1)+", "+s.ph(2)+", "+s.ph(3)+", '')",
		hashResetToken(token), user.ID, expires.Format(time.RFC3339)); err != nil {
		return
	}
	if err := s.recordRecoveryContext(ctx, tx, hashResetToken(token), user.ID); err != nil {
		return
	}
	if err := tx.Commit(); err != nil {
		return
	}
	s.fire(ctx, EventPasswordResetRequested, map[string]string{
		"user_id":    user.ID,
		"email":      user.Email,
		"token":      token,
		"expires_at": expires.Format(time.RFC3339),
	})
}

func (s *Service) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Token == "" || body.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "token and password required"})
		return
	}
	if err := validatePassword(body.Password); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return
	}
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset unavailable"})
		return
	}
	invalid := func() {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "reset link invalid or expired"})
	}
	var userID, expiresAt, used string
	//#nosec G202 -- dialect placeholders only; values parameterized
	if db.QueryRowContext(ctx,
		"SELECT user_id, expires_at, used FROM auth_password_resets WHERE token_hash = "+s.ph(1),
		hashResetToken(strings.TrimSpace(body.Token))).Scan(&userID, &expiresAt, &used) != nil {
		invalid()
		return
	}
	if exp, err := time.Parse(time.RFC3339, expiresAt); err != nil || time.Now().After(exp) || used != "" {
		invalid()
		return
	}
	hash, err := hashPassword(body.Password) // before the transaction: bcrypt must not hold a connection
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"})
		return
	}
	failed := func() { writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "reset failed"}) }
	tokenHash := hashResetToken(strings.TrimSpace(body.Token))
	// One transaction: burn the token, read the issuer and the user, and write
	// the password only while the roles value that was judged is still stored.
	// Everything inside uses the transaction (SQLite has one connection).
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		failed()
		return
	}
	defer func() { _ = tx.Rollback() }()
	//#nosec G202 -- dialect placeholders only; values parameterized
	res, err := tx.ExecContext(ctx, "UPDATE auth_password_resets SET used = 'true' WHERE token_hash = "+s.ph(1)+" AND used = ''", tokenHash)
	if err != nil {
		failed()
		return
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		invalid()
		return
	}
	var issuer string
	//#nosec G202 -- dialect placeholder only; value parameterized
	switch err := tx.QueryRowContext(ctx, "SELECT created_by FROM auth_reset_issuers WHERE token_hash = "+s.ph(1), tokenHash).Scan(&issuer); {
	case errors.Is(err, sql.ErrNoRows):
		issuer = ""
	case err != nil:
		failed()
		return
	}
	// The account row lock comes before anything about the account is read, so a
	// promotion or an email change either committed before the checks below or
	// waits for this transaction.
	if found, err := s.txLockUser(ctx, tx, userID); err != nil {
		failed()
		return
	} else if !found {
		invalid() // the account is gone; the burn is rolled back with nothing else to keep
		return
	}
	target, err := s.txUser(ctx, tx, userID)
	if err != nil {
		failed()
		return
	}
	if target == nil {
		invalid()
		return
	}
	// refuse commits the burn and answers like any invalid token: the token is
	// dead either way and the refusal is not an oracle.
	refuse := func() {
		if err := tx.Commit(); err != nil {
			failed()
			return
		}
		s.fire(ctx, EventCredentialRefused, map[string]string{"type": "reset", "issuer": issuer, "target_id": userID})
		invalid()
	}
	// An administrator-issued token is also void once its issuer is deleted or no
	// longer an administrator; this runs before any effect (F-R6-1).
	if held, err := s.issuerHolds(ctx, tx, issuer); err != nil {
		failed()
		return
	} else if !held {
		refuse()
		return
	}
	// A token is valid for the account as it was when issued. An email change
	// (self-service tokens are delivered by email), a promotion or a demotion
	// since then voids it, whoever issued it.
	holds, err := s.recoveryContextHolds(ctx, tx, tokenHash, target, issuer == "")
	if err != nil {
		failed()
		return
	}
	if !holds {
		refuse()
		return
	}
	prov, err := s.readProvenance(ctx, tx, userID)
	if err != nil {
		failed()
		return
	}
	// The compare-and-set on the roles value just judged still guards the write.
	// An administrator-issued token also stops working once the account is an
	// administrator (unless AUTH_ADMIN_CROSS_CONTROL is on).
	ok := issuer == "" || crossControlAllowed() || !isAdminUser(target)
	if ok {
		ok, err = s.txSetPasswordIfRoles(ctx, tx, userID, hash, target.Roles)
		if err != nil {
			failed()
			return
		}
	}
	if !ok {
		refuse()
		return
	}
	// Credential provenance follows the authority that established the recovery
	// path, not the endpoint that redeemed it: an admin-issued link traces to the
	// admin, a self-service token to whoever set the email it was sent to.
	for _, by := range recoveryProvenanceBy(issuer, prov) {
		if err := s.markProvenance(ctx, tx, userID, fieldPassword, by); err != nil {
			failed()
			return
		}
	}
	// Burn any other outstanding tokens for the user.
	//#nosec G202 -- dialect placeholders only; values parameterized
	if _, err := tx.ExecContext(ctx, "UPDATE auth_password_resets SET used = 'true' WHERE user_id = "+s.ph(1), userID); err != nil {
		failed()
		return
	}
	if err := tx.Commit(); err != nil {
		failed()
		return
	}
	s.fire(ctx, EventPasswordReset, map[string]string{"user_id": userID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "password updated"})
}
