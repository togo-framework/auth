package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Account provenance (auth#6, F12).
//
// Recovery identity is account control: whoever owns the email of record can
// reset the password or sign in through an SSO plugin that links by email, and
// whoever set the password knows it. When an administrator sets either of them
// on somebody else's account, a different administrator who later promotes that
// account would hand it to the first one. auth_account_state records, per field,
// who last set the email and the password when that was not the account holder:
//
//	email_set_by    admin changed the email (PATCH) or created the account
//	password_set_by admin set the password (set-password, create) or redeemed an
//	                admin-issued reset link
//
// The record is STICKY: the holder changing their own password does not clear
// it (the administrator who set it can sign in as the holder and change it
// again), and nothing but an explicit accept on the promotion releases it. A
// later write by somebody else replaces the writer. Self actions never write,
// and the exported SetRoles, SetPassword and CreateUser are trusted-caller APIs
// that write nothing. An absent row means "nothing set by someone else".
//
// The side table is created with CREATE TABLE IF NOT EXISTS like every other
// table of this plugin; users is never altered.

const (
	fieldEmail    = "email"
	fieldPassword = "password"

	// acceptField is the JSON field a promotion request carries to proceed despite
	// provenance set by another administrator. It applies to that one request.
	acceptField = "accept_identity_set_by_other"
)

func ensureAccountStateSQL() string {
	return `CREATE TABLE IF NOT EXISTS auth_account_state (
		user_id text PRIMARY KEY,
		email_set_by text NOT NULL DEFAULT '',
		email_set_at text NOT NULL DEFAULT '',
		password_set_by text NOT NULL DEFAULT '',
		password_set_at text NOT NULL DEFAULT '',
		accepted_by text NOT NULL DEFAULT '',
		accepted_at text NOT NULL DEFAULT ''
	)`
}

// provenance is one account's auth_account_state row (zero value = no row).
type provenance struct {
	EmailBy, EmailAt       string
	PasswordBy, PasswordAt string
}

// markProvenance records that by set field on userID's account. It does nothing
// when by is empty or is the account holder. It must run inside the same
// transaction as the write it describes.
func (s *Service) markProvenance(ctx context.Context, tx *sql.Tx, userID, field, by string) error {
	if by == "" || by == userID {
		return nil
	}
	var q string
	switch field {
	case fieldEmail:
		q = "INSERT INTO auth_account_state (user_id, email_set_by, email_set_at) VALUES (" + s.ph(1) + ", " + s.ph(2) + ", " + s.ph(3) + ") " +
			"ON CONFLICT (user_id) DO UPDATE SET email_set_by = EXCLUDED.email_set_by, email_set_at = EXCLUDED.email_set_at"
	case fieldPassword:
		q = "INSERT INTO auth_account_state (user_id, password_set_by, password_set_at) VALUES (" + s.ph(1) + ", " + s.ph(2) + ", " + s.ph(3) + ") " +
			"ON CONFLICT (user_id) DO UPDATE SET password_set_by = EXCLUDED.password_set_by, password_set_at = EXCLUDED.password_set_at"
	default:
		return errors.New("auth: unknown provenance field")
	}
	//#nosec G202 -- constant statements; dialect placeholders only; values parameterized
	_, err := tx.ExecContext(ctx, q, userID, by, stamp(time.Now()))
	return err
}

// readProvenance loads userID's row inside tx (the zero value when absent).
func (s *Service) readProvenance(ctx context.Context, tx *sql.Tx, userID string) (provenance, error) {
	var p provenance
	//#nosec G202 -- dialect placeholder only; value parameterized
	err := tx.QueryRowContext(ctx,
		"SELECT email_set_by, email_set_at, password_set_by, password_set_at FROM auth_account_state WHERE user_id = "+s.ph(1), userID).
		Scan(&p.EmailBy, &p.EmailAt, &p.PasswordBy, &p.PasswordAt)
	if errors.Is(err, sql.ErrNoRows) {
		return provenance{}, nil
	}
	return p, err
}

// recordAccept notes who explicitly accepted the provenance when promoting
// userID. It is an audit record only: it never releases a later promotion.
func (s *Service) recordAccept(ctx context.Context, tx *sql.Tx, userID, by string) error {
	//#nosec G202 -- dialect placeholders only; values parameterized
	_, err := tx.ExecContext(ctx,
		"INSERT INTO auth_account_state (user_id, accepted_by, accepted_at) VALUES ("+s.ph(1)+", "+s.ph(2)+", "+s.ph(3)+") "+
			"ON CONFLICT (user_id) DO UPDATE SET accepted_by = EXCLUDED.accepted_by, accepted_at = EXCLUDED.accepted_at",
		userID, by, stamp(time.Now()))
	return err
}

// deleteProvenance removes userID's row (account deletion).
func (s *Service) deleteProvenance(ctx context.Context, tx *sql.Tx, userID string) error {
	//#nosec G202 -- dialect placeholder only; value parameterized
	_, err := tx.ExecContext(ctx, "DELETE FROM auth_account_state WHERE user_id = "+s.ph(1), userID)
	return err
}

// taintedFields lists the fields of the account userID that somebody other than
// the holder and the promoter set. It is judged on the provenance stored before
// the promotion request: a write the request itself makes earns no credit.
func (p provenance) taintedFields(userID, promoter string) []string {
	foreign := func(by string) bool { return by != "" && by != userID && by != promoter }
	var out []string
	if foreign(p.EmailBy) {
		out = append(out, fieldEmail)
	}
	if foreign(p.PasswordBy) {
		out = append(out, fieldPassword)
	}
	sort.Strings(out)
	return out
}

// provenanceConflict is the 409 a promotion gets when the account carries
// identity set by another administrator and the request did not accept it. The
// body names the condition so a UI can ask for an explicit confirmation; a
// client must never retry with the accept field without that confirmation.
func provenanceConflict(p provenance, tainted []string) error {
	setBy := map[string]string{}
	setAt := map[string]string{}
	for _, f := range tainted {
		switch f {
		case fieldEmail:
			setBy[f], setAt[f] = p.EmailBy, p.EmailAt
		case fieldPassword:
			setBy[f], setAt[f] = p.PasswordBy, p.PasswordAt
		}
	}
	return &httpError{
		status: http.StatusConflict,
		msg:    "identity_set_by_other_admin: " + strings.Join(tainted, ",") + " of this account was set by another administrator; promoting it requires explicit confirmation",
		body: map[string]any{
			"error":          "identity_set_by_other_admin",
			"message":        "The " + strings.Join(tainted, " and ") + " of this account was set by another administrator. Promoting it would give that administrator a way into an administrator account. Confirm explicitly to proceed.",
			"tainted_fields": tainted,
			"set_by":         setBy,
			"set_at":         setAt,
			"accept_field":   acceptField,
		},
	}
}
