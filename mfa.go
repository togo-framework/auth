package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //#nosec G505 -- TOTP (RFC 6238) mandates HMAC-SHA1
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// MFA: one-time passwords (email/SMS/etc. delivered via an event), TOTP 2FA
// (RFC 6238), and a PIN for lock-screen unlock. Delivery is decoupled: requesting
// an OTP fires EventOTPRequested with the code so a mail/notifications/SMS plugin
// (or app listener) sends it — auth itself sends nothing.

// EventOTPRequested carries {subject, code, purpose} for delivery plugins.
const EventOTPRequested = "auth.otp.requested"

func (s *Service) ensureMFASchema(ctx context.Context) error {
	db, err := s.k.SQL(ctx)
	if err != nil {
		return err
	}
	for _, ddl := range []string{
		`CREATE TABLE IF NOT EXISTS otp_codes (subject text NOT NULL, purpose text NOT NULL, code_hash text NOT NULL, expires_at text NOT NULL, PRIMARY KEY (subject, purpose))`,
		`CREATE TABLE IF NOT EXISTS auth_totp (subject text PRIMARY KEY, secret text NOT NULL, enabled text NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS auth_pins (subject text PRIMARY KEY, pin_hash text NOT NULL)`,
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ph(n int) string { return s.k.Dialect().Placeholder(n) }

// --- OTP -----------------------------------------------------------------

func (s *Service) handleOTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
		return
	}
	if body.Purpose == "" {
		body.Purpose = "login"
	}
	code := fmt.Sprintf("%06d", randUint32()%1000000)
	hash, _ := hashPassword(code)
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "otp unavailable"})
		return
	}
	exp := time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339)
	q := "INSERT INTO otp_codes (subject, purpose, code_hash, expires_at) VALUES (" + //#nosec G202 -- dialect placeholders only; values parameterized
		s.ph(1) + ", " + s.ph(2) + ", " + s.ph(3) + ", " + s.ph(4) + ") ON CONFLICT (subject, purpose) DO UPDATE SET code_hash = " + s.ph(3) + ", expires_at = " + s.ph(4)
	if _, err := db.ExecContext(ctx, q, body.Email, body.Purpose, hash, exp); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "otp store failed"})
		return
	}
	// Decoupled delivery: a mail/sms/notifications plugin listens and sends it.
	s.fire(ctx, EventOTPRequested, map[string]string{"subject": body.Email, "code": code, "purpose": body.Purpose})
	writeJSON(w, http.StatusOK, map[string]string{"status": "otp sent"})
}

func (s *Service) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email   string `json:"email"`
		Purpose string `json:"purpose"`
		Code    string `json:"code"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || body.Email == "" || body.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and code required"})
		return
	}
	if body.Purpose == "" {
		body.Purpose = "login"
	}
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "otp unavailable"})
		return
	}
	var hash, exp string
	//#nosec G202 -- dialect placeholders only; values parameterized
	row := db.QueryRowContext(ctx, "SELECT code_hash, expires_at FROM otp_codes WHERE subject = "+s.ph(1)+" AND purpose = "+s.ph(2), body.Email, body.Purpose)
	if row.Scan(&hash, &exp) != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}
	if t, err := time.Parse(time.RFC3339, exp); err != nil || time.Now().After(t) || !checkPassword(hash, body.Code) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired code"})
		return
	}
	//#nosec G202 -- dialect placeholders only; values parameterized
	_, _ = db.ExecContext(ctx, "DELETE FROM otp_codes WHERE subject = "+s.ph(1)+" AND purpose = "+s.ph(2), body.Email, body.Purpose)
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// --- TOTP 2FA (RFC 6238) -------------------------------------------------

func (s *Service) handle2FAEnroll(w http.ResponseWriter, r *http.Request) {
	id, _ := IdentityFrom(r.Context())
	secret := newTOTPSecret()
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	q := "INSERT INTO auth_totp (subject, secret, enabled) VALUES (" + s.ph(1) + ", " + s.ph(2) + ", '') " + //#nosec G202 -- dialect placeholders only; values parameterized
		"ON CONFLICT (subject) DO UPDATE SET secret = " + s.ph(2) + ", enabled = ''"
	if _, err := db.ExecContext(ctx, q, id.ID, secret); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "enroll failed"})
		return
	}
	issuer := "togo"
	uri := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, url.QueryEscape(id.Email), secret, issuer)
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": uri})
}

func (s *Service) handle2FAVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id, _ := IdentityFrom(r.Context())
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	var secret string
	//#nosec G202 -- dialect placeholders only; values parameterized
	if db.QueryRowContext(ctx, "SELECT secret FROM auth_totp WHERE subject = "+s.ph(1), id.ID).Scan(&secret) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not enrolled"})
		return
	}
	if !totpValid(secret, body.Code) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
		return
	}
	//#nosec G202 -- dialect placeholders only; values parameterized
	_, _ = db.ExecContext(ctx, "UPDATE auth_totp SET enabled = 'true' WHERE subject = "+s.ph(1), id.ID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa enabled"})
}

// --- PIN (lock screen) ---------------------------------------------------

func (s *Service) handlePINSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PIN string `json:"pin"`
	}
	if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.PIN) < 4 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "pin must be at least 4 digits"})
		return
	}
	id, _ := IdentityFrom(r.Context())
	hash, _ := hashPassword(body.PIN)
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	q := "INSERT INTO auth_pins (subject, pin_hash) VALUES (" + s.ph(1) + ", " + s.ph(2) + ") " + //#nosec G202 -- dialect placeholders only; values parameterized
		"ON CONFLICT (subject) DO UPDATE SET pin_hash = " + s.ph(2)
	if _, err := db.ExecContext(ctx, q, id.ID, hash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pin set failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "pin set"})
}

func (s *Service) handlePINVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PIN string `json:"pin"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	id, _ := IdentityFrom(r.Context())
	ctx := r.Context()
	db, err := s.k.SQL(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unavailable"})
		return
	}
	var hash string
	//#nosec G202 -- dialect placeholders only; values parameterized
	if db.QueryRowContext(ctx, "SELECT pin_hash FROM auth_pins WHERE subject = "+s.ph(1), id.ID).Scan(&hash) != nil || !checkPassword(hash, body.PIN) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid pin"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unlocked"})
}

// --- TOTP primitives -----------------------------------------------------

func newTOTPSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

func totpValid(secret, code string) bool {
	now := time.Now()
	for _, skew := range []time.Duration{0, -30 * time.Second, 30 * time.Second} {
		if totpAt(secret, now.Add(skew)) == code {
			return true
		}
	}
	return false
}

func totpAt(secret string, t time.Time) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return ""
	}
	buf := make([]byte, 8)
	//#nosec G115 -- t.Unix() is always positive (post-1970)
	binary.BigEndian.PutUint64(buf, uint64(t.Unix())/30)
	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

func randUint32() uint32 {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return binary.BigEndian.Uint32(b)
}
