package auth

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPIgnoresSpoofedForwarding(t *testing.T) {
	t.Setenv("CLIENT_IP_HEADER", "")
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("SECURITY: a direct client must not choose its own address, got %s", got)
	}
}

func TestClientIPBehindTrustedProxies(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "127.0.0.1,10.0.0.0/8")
	t.Setenv("CLIENT_IP_HEADER", "")
	r := httptest.NewRequest("POST", "/api/auth/login", nil)
	r.RemoteAddr = "127.0.0.1:4000"
	// The attacker's own value is leftmost; proxies append what they saw.
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 198.51.100.7, 10.10.10.1")
	if got := clientIP(r); got != "198.51.100.7" {
		t.Fatalf("want the first untrusted hop from the right, got %s", got)
	}
}

func TestClientIPHeaderOnlyFromTrustedProxy(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "127.0.0.1")
	t.Setenv("CLIENT_IP_HEADER", "CF-Connecting-IP")
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("CF-Connecting-IP", "198.51.100.8")
	if got := clientIP(r); got != "198.51.100.8" {
		t.Fatalf("trusted proxy header ignored, got %s", got)
	}
	r.RemoteAddr = "203.0.113.1:4000"
	if got := clientIP(r); got != "203.0.113.1" {
		t.Fatalf("SECURITY: header from an untrusted peer must be ignored, got %s", got)
	}
}
