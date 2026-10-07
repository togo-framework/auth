package auth

import "context"

// Auth lifecycle events fired on the kernel hook bus. Apps subscribe via
// k.Hooks.On(auth.EventLogin, 50, fn) to inject behavior — audit logging, welcome
// mail, post-login/redirect decisions, etc. Listeners run in priority order.
const (
	EventRegistered      = "auth.registered"
	EventLogin           = "auth.login"
	EventLogout          = "auth.logout"
	EventPasswordChanged = "auth.password_changed"
	EventLoginFailed     = "auth.login_failed"

	// EventPasswordResetRequested carries {user_id, email, token, expires_at}.
	// A mail/SMS/notifications listener delivers the reset link; the token is
	// never returned over HTTP.
	EventPasswordResetRequested = "auth.password_reset_requested"
	EventPasswordReset          = "auth.password_reset"
	// EventLoginChallenged fires when a password login is held for 2FA.
	EventLoginChallenged = "auth.login_challenged"

	// Admin user-management events. Every payload is a map[string]string that
	// names the acting administrator (actor_id) and never carries a secret: no
	// token, link or password.
	EventUserCreated = "auth.user_created" // actor_id, target_id, user_id, email
	EventUserUpdated = "auth.user_updated" // actor_id, target_id, user_id, fields (names only)
	EventUserDeleted = "auth.user_deleted" // actor_id, target_id, user_id, email
	// EventUserImpersonated: actor_id, target_id, at, expires_at.
	EventUserImpersonated = "auth.user_impersonated"
	// EventImpersonationEnded: actor_id, target_id, at.
	EventImpersonationEnded = "auth.impersonation_ended"
	// EventMagicLinkIssued: actor_id, user_id, expires_at. The link itself goes
	// only to the administrator who asked for it, in the HTTP response.
	EventMagicLinkIssued = "auth.magic_link_issued"
	// EventMagicLinkRedeemed: actor_id (the issuing admin), target_id, at.
	EventMagicLinkRedeemed = "auth.magic_link_redeemed"
	// EventAdminCrossControl is fired for every operation one administrator
	// performs on another under the AUTH_ADMIN_CROSS_CONTROL exception:
	// actor_id, target_id, operation, policy ("AUTH_ADMIN_CROSS_CONTROL").
	EventAdminCrossControl = "auth.admin_cross_control"
	// EventAdminResetLinkIssued: actor_id, user_id, expires_at (no link).
	EventAdminResetLinkIssued = "auth.admin_reset_link_issued"
	// EventAdminPromoted fires when an account becomes an administrator through
	// the admin API: actor_id, target_id, tainted (comma-joined fields whose
	// email/password another administrator set, empty if none), accepted
	// ("true" when the promoter explicitly accepted that, else "false").
	EventAdminPromoted = "auth.admin_promoted"
	// EventAdminDemoted fires when an administrator loses the role through the
	// admin API: actor_id, target_id.
	EventAdminDemoted = "auth.admin_demoted"
	// EventCredentialRefused fires when an admin-issued credential (a reset link
	// redemption or an admin-set password) is refused because the account is, or
	// became, an administrator or changed under the operation: type ("reset" or
	// "set-password"), issuer (the administrator), target_id. Never the token.
	EventCredentialRefused = "auth.credential_refused"
)

// fire dispatches an auth event on the kernel hook bus (no-op if unavailable).
func (s *Service) fire(ctx context.Context, event string, payload any) {
	if s.k.Hooks != nil {
		_ = s.k.Hooks.Fire(ctx, event, payload)
	}
}
