package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// Impersonation: an administrator receives a bearer token that acts as another
// account, so they can see what that user sees.
//
// The token is distinguishable from a login and bounded:
//   - it carries an `act.sub` claim (RFC 8693) naming the administrator, and a
//     jti, and /api/auth/me reports it as `impersonator`;
//   - it lives AUTH_IMPERSONATION_TTL_MINUTES (default 30, capped at 480);
//   - it is returned in the response body only, never as a cookie, so the
//     administrator's own session is untouched and ending the impersonation is
//     just dropping the token (POST /api/auth/impersonation/stop also revokes
//     it server-side and writes the audit event);
//   - it dies at once if it is stopped, or the administrator loses the role,
//     or either account is deleted;
//   - it can not reach the admin API, nor change the borrowed account's password,
//     2FA, PIN or API tokens.
//
// Impersonating another administrator is refused unless the single
// AUTH_ADMIN_CROSS_CONTROL=true policy is on (it governs every cross-admin
// operation and audits each use): it would hand one administrator another's
// powers under another's name. Impersonating yourself is
// refused as pointless.

const (
	defaultImpersonationTTL = 30 * time.Minute
	maxImpersonationTTL     = 8 * time.Hour
)

func impersonationTTL() time.Duration {
	if v := os.Getenv("AUTH_IMPERSONATION_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			d := time.Duration(n) * time.Minute
			if d > maxImpersonationTTL {
				return maxImpersonationTTL
			}
			return d
		}
	}
	return defaultImpersonationTTL
}

func crossControlAllowed() bool {
	return strings.EqualFold(os.Getenv("AUTH_ADMIN_CROSS_CONTROL"), "true")
}

func (s *Service) adminImpersonate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor, _ := IdentityFrom(ctx)
	if actor == nil {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	target, err := s.userByID(ctx, chi.URLParam(r, "id"))
	if err != nil {
		s.adminInternal(w, "load user", err)
		return
	}
	if target == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	if target.ID == actor.ID {
		writeErr(w, http.StatusBadRequest, "you cannot impersonate yourself")
		return
	}
	if s.refuseAdminTarget(w, r, target) {
		return
	}

	ttl := impersonationTTL()
	id := *target.identity(s.def)
	id.Impersonator = actor.ID
	tok, err := s.signToken(id, ttl)
	if err != nil {
		s.adminInternal(w, "sign impersonation token", err)
		return
	}
	now := time.Now()
	exp := now.Add(ttl)
	s.auditCross(ctx, actor.ID, target, "impersonate")
	s.fire(ctx, EventUserImpersonated, map[string]string{
		"actor_id": actor.ID, "target_id": target.ID, "at": stamp(now), "expires_at": stamp(exp),
	})
	writeJSON(w, http.StatusOK, map[string]any{"token": tok, "identity": id, "expires_at": stamp(exp)})
}

// handleImpersonationStop ends the caller's impersonation: it revokes the
// token and records who stopped acting as whom.
func (s *Service) handleImpersonationStop(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	if id == nil || id.Impersonator == "" || id.TokenID == "" {
		writeErr(w, http.StatusBadRequest, "not impersonating")
		return
	}
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		s.adminInternal(w, "stop impersonation", err)
		return
	}
	now := time.Now()
	// Sweep records that outlived any token they could have revoked, then revoke.
	//#nosec G202 -- dialect placeholder only; value parameterized
	if _, err := db.ExecContext(ctx, "DELETE FROM auth_revoked_tokens WHERE expires_at < "+s.ph(1), stamp(now)); err != nil {
		s.adminInternal(w, "stop impersonation", err)
		return
	}
	//#nosec G202 -- dialect placeholders only; values parameterized
	// Idempotent: concurrent stops of one token all succeed, one records the end.
	res, err := db.ExecContext(ctx, "INSERT INTO auth_revoked_tokens (jti, expires_at) VALUES ("+s.ph(1)+", "+s.ph(2)+") ON CONFLICT (jti) DO NOTHING", id.TokenID, stamp(now.Add(maxImpersonationTTL)))
	if err != nil {
		s.adminInternal(w, "stop impersonation", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	s.fire(ctx, EventImpersonationEnded, map[string]string{"actor_id": id.Impersonator, "target_id": id.ID, "at": stamp(now)})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

var errImpersonationInvalid = errors.New("impersonation no longer valid")

// checkImpersonation fails closed unless the token is unrevoked, the actor is
// still an administrator and the target still exists.
func (s *Service) checkImpersonation(ctx context.Context, id *Identity) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	var one int
	//#nosec G202 -- dialect placeholder only; value parameterized
	switch err := db.QueryRowContext(ctx, "SELECT 1 FROM auth_revoked_tokens WHERE jti = "+s.ph(1), id.TokenID).Scan(&one); err {
	case sql.ErrNoRows:
	case nil:
		return errImpersonationInvalid
	default:
		return err
	}
	actor, err := s.userByID(ctx, id.Impersonator)
	if err != nil {
		return err
	}
	if actor == nil || !isAdminUser(actor) {
		return errImpersonationInvalid
	}
	target, err := s.userByID(ctx, id.ID)
	if err != nil {
		return err
	}
	if target == nil {
		return errImpersonationInvalid
	}
	// An act-limited session (impersonation or magic link) must not outlive
	// the target becoming an administrator: it would be a way into that
	// account that the cross-control rule forbids at issue time.
	if isAdminUser(target) && !crossControlAllowed() {
		return errImpersonationInvalid
	}
	return nil
}
