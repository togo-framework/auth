package auth

import (
	"testing"
)

func TestValidEmail(t *testing.T) {
	for email, want := range map[string]bool{
		"a@b.co":          true,
		"first.last@x.io": true,
		"bad":             false,
		"a@b":             false,
		"@b.co":           false,
		"Fady <a@b.co>":   false,
		"<a@b.co>":        false,
		"a@b.co, c@d.co":  false,
	} {
		if got := validEmail(email); got != want {
			t.Errorf("validEmail(%q) = %v, want %v", email, got, want)
		}
	}
}
