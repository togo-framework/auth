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

	// Admin user-management events. Apps/plugins (audit, mail) subscribe to react —
	// e.g. the mail plugin delivers the magic/reset link from EventMagicLinkIssued.
	EventUserCreated      = "auth.user_created"
	EventUserUpdated      = "auth.user_updated"
	EventUserDeleted      = "auth.user_deleted"
	EventUserImpersonated = "auth.user_impersonated"
	EventMagicLinkIssued  = "auth.magic_link_issued"
	EventPasswordReset    = "auth.password_reset"
)

// fire dispatches an auth event on the kernel hook bus (no-op if unavailable).
func (s *Service) fire(ctx context.Context, event string, payload any) {
	if s.k.Hooks != nil {
		_ = s.k.Hooks.Fire(ctx, event, payload)
	}
}
