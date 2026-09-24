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
)

// fire dispatches an auth event on the kernel hook bus (no-op if unavailable).
func (s *Service) fire(ctx context.Context, event string, payload any) {
	if s.k.Hooks != nil {
		_ = s.k.Hooks.Fire(ctx, event, payload)
	}
}
