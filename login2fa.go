package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Two-factor login. Before v0.9.0, /api/auth/login issued a full session even
// when the user had TOTP enabled, so 2FA was enrollable but never enforced.
// Now a password login for a 2FA user returns a short-lived signed challenge
// instead of a session, and POST /api/auth/2fa/challenge exchanges the
// challenge plus a valid code for the session.
//
// Other plugins (auth-mfa) can require extra factors through RegisterSecondFactor
// and verify them against the same challenge via VerifyLoginChallenge, so there
// is one challenge format and one signing key (AUTH_SECRET).

// LoginChallengeTTL is how long a user has to enter their code.
const LoginChallengeTTL = 5 * time.Minute

// maxChallengeAttempts caps wrong codes per challenge, so a six-digit code
// cannot be brute-forced within one challenge.
const maxChallengeAttempts = 5

// SecondFactor reports whether a user must pass an extra factor at login.
type SecondFactor func(ctx context.Context, userID string) bool

var (
	secondFactorsMu sync.RWMutex
	secondFactors   []SecondFactor
)

// RegisterSecondFactor adds a check consulted at login (auth-mfa registers one).
func RegisterSecondFactor(f SecondFactor) {
	secondFactorsMu.Lock()
	defer secondFactorsMu.Unlock()
	secondFactors = append(secondFactors, f)
}

// SecondFactorRequired reports whether the user must complete 2FA before a
// session is issued: core TOTP enabled, or any registered second factor.
func (s *Service) SecondFactorRequired(ctx context.Context, userID string) bool {
	if s.totpEnabled(ctx, userID) {
		return true
	}
	secondFactorsMu.RLock()
	defer secondFactorsMu.RUnlock()
	for _, f := range secondFactors {
		if f(ctx, userID) {
			return true
		}
	}
	return false
}

func (s *Service) totpEnabled(ctx context.Context, userID string) bool {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return false
	}
	var enabled string
	//#nosec G202 -- dialect placeholders only; values parameterized
	if db.QueryRowContext(ctx, "SELECT enabled FROM auth_totp WHERE subject = "+s.ph(1), userID).Scan(&enabled) != nil {
		return false
	}
	return enabled == "true"
}

type loginChallenge struct {
	UserID  string `json:"uid"`
	Purpose string `json:"p"`
	Nonce   string `json:"n"`
	Exp     int64  `json:"exp"`
}

// IssueLoginChallenge mints a signed, short-lived challenge for a user who has
// passed their password but still owes a second factor. It is not a session.
func (s *Service) IssueLoginChallenge(userID string) (string, error) {
	c := loginChallenge{UserID: userID, Purpose: "login-2fa", Nonce: randomToken(), Exp: time.Now().Add(LoginChallengeTTL).Unix()}
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + s.signChallenge(payload), nil
}

// VerifyLoginChallenge validates a challenge and returns its user id.
func (s *Service) VerifyLoginChallenge(token string) (string, error) {
	userID, _, err := s.parseLoginChallenge(token)
	return userID, err
}

func (s *Service) parseLoginChallenge(token string) (userID, nonce string, err error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(s.signChallenge(parts[0]))) {
		return "", "", errors.New("invalid challenge")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", errors.New("invalid challenge")
	}
	var c loginChallenge
	if json.Unmarshal(raw, &c) != nil || c.Purpose != "login-2fa" || c.UserID == "" {
		return "", "", errors.New("invalid challenge")
	}
	if time.Now().Unix() > c.Exp {
		return "", "", errors.New("challenge expired")
	}
	return c.UserID, c.Nonce, nil
}

// signChallenge uses a key derived from AUTH_SECRET, domain-separated so a
// challenge can never be confused with a session JWT.
func (s *Service) signChallenge(payload string) string {
	key := hmac.New(sha256.New, s.secret)
	key.Write([]byte("togo/auth/login-challenge/v1"))
	mac := hmac.New(sha256.New, key.Sum(nil))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// challengeAttempts counts wrong codes per challenge nonce and remembers used
// nonces, so a challenge is single-use and brute force is capped.
type challengeAttempts struct {
	mu    sync.Mutex
	fails map[string]int
	used  map[string]time.Time
}

var attempts = &challengeAttempts{fails: map[string]int{}, used: map[string]time.Time{}}

func (a *challengeAttempts) blocked(nonce string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gc()
	_, used := a.used[nonce]
	return used || a.fails[nonce] >= maxChallengeAttempts
}

func (a *challengeAttempts) fail(nonce string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fails[nonce]++
}

func (a *challengeAttempts) consume(nonce string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.used[nonce] = time.Now()
	delete(a.fails, nonce)
}

// gc drops nonces older than a challenge can live. Caller holds the lock.
func (a *challengeAttempts) gc() {
	cutoff := time.Now().Add(-2 * LoginChallengeTTL)
	for n, at := range a.used {
		if at.Before(cutoff) {
			delete(a.used, n)
		}
	}
	if len(a.fails) > 10000 {
		a.fails = map[string]int{}
	}
}

// handle2FAChallenge completes a 2FA login: challenge + TOTP code → session.
func (s *Service) handle2FAChallenge(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Challenge == "" || body.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge and code required"})
		return
	}
	ctx := r.Context()
	userID, nonce, err := s.parseLoginChallenge(body.Challenge)
	if err != nil || attempts.blocked(nonce) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "challenge invalid or expired; sign in again"})
		return
	}
	if !s.verifyUserTOTP(ctx, userID, body.Code) {
		attempts.fail(nonce)
		s.fire(ctx, EventLoginFailed, map[string]string{"user_id": userID, "reason": "2fa"})
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}
	attempts.consume(nonce)
	s.completeLogin(w, ctx, userID)
}

// CompleteLogin issues the session for a user who has passed every factor.
// Exported so second-factor plugins finish logins the same way.
func (s *Service) CompleteLogin(w http.ResponseWriter, ctx context.Context, userID string) {
	s.completeLogin(w, ctx, userID)
}

func (s *Service) completeLogin(w http.ResponseWriter, ctx context.Context, userID string) {
	// Load the full identity so the session carries roles and permissions.
	id, err := s.Guard("").Auth.ByID(ctx, userID)
	if err != nil || id == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "account unavailable"})
		return
	}
	token, err := s.IssueToken(*id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login failed"})
		return
	}
	s.startSession(w, ctx, token)
	s.fire(ctx, EventLogin, id)
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "user": id})
}

func (s *Service) verifyUserTOTP(ctx context.Context, userID, code string) bool {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return false
	}
	var secret, enabled string
	//#nosec G202 -- dialect placeholders only; values parameterized
	if db.QueryRowContext(ctx, "SELECT secret, enabled FROM auth_totp WHERE subject = "+s.ph(1), userID).Scan(&secret, &enabled) != nil {
		return false
	}
	return enabled == "true" && totpValid(secret, strings.TrimSpace(code))
}
