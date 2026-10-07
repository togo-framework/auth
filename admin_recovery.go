package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Recovery credentials and security-boundary transitions (auth#6, F-R5-1c).
//
// A reset or magic-link token is a promise made at issuance: "whoever holds
// this may recover THAT account as it was then". An email change or a change of
// administrator status alters what the promise means, so a token never outlives
// such a transition. Every token carries the context it was issued against in
// auth_recovery_context, and redemption re-checks it inside the redeem
// transaction, after the account row lock:
//
//	self-service reset  email of record, who set that email, administrator
//	                    status, privilege epoch
//	admin-issued reset  administrator status, privilege epoch
//	magic link          administrator status, privilege epoch
//
// The privilege epoch (auth_priv_epoch) counts promotions and demotions, so a
// promote-then-demote round trip is detected even though the status is the
// same again. A token with no context row (issued before this table existed) is
// refused: a refusal is the safe direction and a token lives minutes.
//
// A refused token is burned and the burn is committed, and the response is the
// same 401 as any other invalid token, so the refusal is not an oracle.

func ensureRecoveryContextSQL() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS auth_recovery_context (
			token_hash text PRIMARY KEY,
			user_id text NOT NULL,
			email text NOT NULL DEFAULT '',
			email_by text NOT NULL DEFAULT '',
			admin text NOT NULL DEFAULT '',
			priv_ver integer NOT NULL DEFAULT 0,
			issued_at text NOT NULL DEFAULT ''
		)`,
		`CREATE TABLE IF NOT EXISTS auth_priv_epoch (
			user_id text PRIMARY KEY,
			ver integer NOT NULL DEFAULT 0
		)`,
	}
}

// recoveryContext is what a token was issued against.
type recoveryContext struct {
	Email, EmailBy string
	Admin          bool
	PrivVer        int
}

func adminFlag(b bool) string {
	if b {
		return "admin"
	}
	return ""
}

// bumpPrivEpoch records a promotion or demotion of userID. It must run inside
// the transaction that changes the roles.
func (s *Service) bumpPrivEpoch(ctx context.Context, tx *sql.Tx, userID string) error {
	//#nosec G202 -- dialect placeholder only; value parameterized
	_, err := tx.ExecContext(ctx,
		"INSERT INTO auth_priv_epoch (user_id, ver) VALUES ("+s.ph(1)+", 1) "+
			"ON CONFLICT (user_id) DO UPDATE SET ver = auth_priv_epoch.ver + 1", userID)
	return err
}

func (s *Service) privEpoch(ctx context.Context, tx *sql.Tx, userID string) (int, error) {
	var v int
	//#nosec G202 -- dialect placeholder only; value parameterized
	err := tx.QueryRowContext(ctx, "SELECT ver FROM auth_priv_epoch WHERE user_id = "+s.ph(1), userID).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// currentRecoveryContext is the account's state now, read inside tx.
func (s *Service) currentRecoveryContext(ctx context.Context, tx *sql.Tx, u *User) (recoveryContext, error) {
	prov, err := s.readProvenance(ctx, tx, u.ID)
	if err != nil {
		return recoveryContext{}, err
	}
	ver, err := s.privEpoch(ctx, tx, u.ID)
	if err != nil {
		return recoveryContext{}, err
	}
	return recoveryContext{Email: u.Email, EmailBy: prov.EmailBy, Admin: isAdminUser(u), PrivVer: ver}, nil
}

// recordRecoveryContext stores the context token tokenHash is issued against.
// It runs in the issuing transaction; a transition that commits between this
// read and the token becoming usable only makes the token stale, never valid.
func (s *Service) recordRecoveryContext(ctx context.Context, tx *sql.Tx, tokenHash, userID string) error {
	u, err := s.txUser(ctx, tx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		return errAccountGone
	}
	c, err := s.currentRecoveryContext(ctx, tx, u)
	if err != nil {
		return err
	}
	//#nosec G202 -- dialect placeholders only; values parameterized
	_, err = tx.ExecContext(ctx,
		"INSERT INTO auth_recovery_context (token_hash, user_id, email, email_by, admin, priv_ver, issued_at) VALUES ("+
			s.ph(1)+", "+s.ph(2)+", "+s.ph(3)+", "+s.ph(4)+", "+s.ph(5)+", "+s.ph(6)+", "+s.ph(7)+")",
		tokenHash, userID, c.Email, c.EmailBy, adminFlag(c.Admin), c.PrivVer, stamp(time.Now()))
	return err
}

// recoveryContextHolds reports whether the token's issuance context still
// describes the account u (read after the row lock, inside tx). bindEmail adds
// the email-channel checks that apply to a self-service token. A missing
// context row is a refusal.
func (s *Service) recoveryContextHolds(ctx context.Context, tx *sql.Tx, tokenHash string, u *User, bindEmail bool) (bool, error) {
	var issued recoveryContext
	var admin string
	//#nosec G202 -- dialect placeholder only; value parameterized
	err := tx.QueryRowContext(ctx,
		"SELECT email, email_by, admin, priv_ver FROM auth_recovery_context WHERE token_hash = "+s.ph(1), tokenHash).
		Scan(&issued.Email, &issued.EmailBy, &admin, &issued.PrivVer)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	issued.Admin = admin != ""
	now, err := s.currentRecoveryContext(ctx, tx, u)
	if err != nil {
		return false, err
	}
	if issued.Admin != now.Admin || issued.PrivVer != now.PrivVer {
		return false, nil
	}
	if bindEmail && (issued.Email != now.Email || issued.EmailBy != now.EmailBy) {
		return false, nil
	}
	return true, nil
}

// recoveryProvenanceBy is who a credential set through a recovery channel
// traces to: the administrator who issued the link, or for a self-service token
// whoever set the email it was delivered to. Credential provenance follows the
// authority that established the recovery path, not the endpoint that redeemed
// it. "" means the holder's own path. markProvenance ignores the holder.
func recoveryProvenanceBy(issuer string, prov provenance) string {
	if issuer != "" {
		return issuer
	}
	return prov.EmailBy
}
