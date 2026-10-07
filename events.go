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
	EventUserCreated = "auth.user_created" // actor_id, user_id, email
	EventUserUpdated = "auth.user_updated" // actor_id, user_id, fields
	EventUserDeleted = "auth.user_deleted" // actor_id, user_id, email
	// EventUserImpersonated: actor_id, target_id, at, expires_at.
	EventUserImpersonated = "auth.user_impersonated"
	// EventImpersonationEnded: actor_id, target_id, at.
	EventImpersonationEnded = "auth.impersonation_ended"
	// EventMagicLinkIssued: actor_id, user_id, expires_at. The link itself goes
	// only to the administrator who asked for it, in the HTTP response.
	EventMagicLinkIssued = "auth.magic_link_issued"
	// EventAdminResetLinkIssued: actor_id, user_id, expires_at (no link).
	EventAdminResetLinkIssued = "auth.admin_reset_link_issued"
)

// fire dispatches an auth event on the kernel hook bus (no-op if unavailable).
func (s *Service) fire(ctx context.Context, event string, payload any) {
	if s.k.Hooks != nil {
		_ = s.k.Hooks.Fire(ctx, event, payload)
	}
}
