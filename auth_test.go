package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testService(secret string) *Service {
	return &Service{secret: []byte(secret), ttl: time.Hour, guards: map[string]*Guard{}, def: "api"}
}

func TestTokenRoundTrip(t *testing.T) {
	s := testService("a-sufficiently-long-test-secret-string!!")
	id := Identity{ID: "u1", Email: "a@b.c", Roles: []string{"admin"}, Permissions: []string{"posts.write"}, Guard: "api"}
	tok, err := s.IssueToken(id)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.ID != "u1" || !out.HasRole("admin") || !out.Can("posts.write") {
		t.Fatalf("identity mismatch: %+v", out)
	}
}

func TestVerifyRejectsForgedSecret(t *testing.T) {
	tok, _ := testService("secret-number-one-aaaaaaaaaaaaaaaaaaaa").IssueToken(Identity{ID: "u1"})
	if _, err := testService("secret-number-two-bbbbbbbbbbbbbbbbbbbb").Verify(tok); err == nil {
		t.Fatal("token signed with a different secret must be rejected")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	s := testService("a-sufficiently-long-test-secret-string!!")
	claims := jwt.MapClaims{"sub": "u1", "iss": "togo", "exp": time.Now().Add(-time.Hour).Unix()}
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("expired token must be rejected")
	}
}

func TestVerifyRejectsNoExpiry(t *testing.T) {
	s := testService("a-sufficiently-long-test-secret-string!!")
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "u1", "iss": "togo"}).SignedString(s.secret)
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("token without exp must be rejected (WithExpirationRequired)")
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	s := testService("a-sufficiently-long-test-secret-string!!")
	tok, _ := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "u1", "iss": "togo", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if _, err := s.Verify(tok); err == nil {
		t.Fatal("alg=none token must be rejected")
	}
}

func TestPasswordPolicy(t *testing.T) {
	if validatePassword("short") == nil {
		t.Fatal("too-short password must be rejected")
	}
	if err := validatePassword("longenough123"); err != nil {
		t.Fatalf("valid password rejected: %v", err)
	}
	long := make([]byte, 80)
	for i := range long {
		long[i] = 'a'
	}
	if validatePassword(string(long)) == nil {
		t.Fatal("password over 72 bytes must be rejected")
	}
}
