package auth

import (
	"context"
	"errors"
	"net/mail"
	"strings"
)

// normalizeEmail is the canonical form accounts are stored and matched in:
// trimmed and lower-cased, so Fady@x.com and fady@x.com are one account.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// validEmail reports whether email (already normalised) is a bare address
// like a@b.co — no display name, no angle brackets, and a dotted domain.
func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	if err != nil || a.Name != "" || a.Address != email {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	return at > 0 && strings.Contains(email[at+1:], ".")
}

// userByEmail finds an account by email regardless of case. Rows written
// before emails were normalised keep their original casing, so an exact match
// on the trimmed input is tried when the normalised form finds nothing.
func (s *Service) userByEmail(ctx context.Context, email string) (*User, error) {
	norm := normalizeEmail(email)
	u, err := s.users().Where("email", "=", norm).First(ctx)
	if err != nil || u != nil {
		return u, err
	}
	if raw := strings.TrimSpace(email); raw != norm {
		return s.users().Where("email", "=", raw).First(ctx)
	}
	return nil, nil
}

var errInvalidEmail = errors.New("a valid email address is required")
