package mfa

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1, truncated to 6 digits.
func TestCodeRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for unix, want := range map[int64]string{
		59: "287082", 1111111109: "081804", 1111111111: "050471",
		1234567890: "005924", 2000000000: "279037", 20000000000: "353130",
	} {
		if got := Code(secret, Step(time.Unix(unix, 0))); got != want {
			t.Errorf("t=%d: %s, want %s", unix, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_700_000_000, 0)
	cur := Step(now)
	for _, tt := range []struct {
		code string
		skew int
		step int64
		ok   bool
	}{
		{Code(secret, cur), 1, cur, true},
		{" " + Code(secret, cur) + " ", 1, cur, true},
		{Code(secret, cur-1), 1, cur - 1, true},
		{Code(secret, cur+1), 1, cur + 1, true},
		{Code(secret, cur-2), 1, 0, false},
		{Code(secret, cur-1), 0, 0, false},
		{"12345", 1, 0, false},
		{"", 1, 0, false},
	} {
		step, ok := Validate(secret, tt.code, now, tt.skew)
		if ok != tt.ok || (ok && step != tt.step) {
			t.Errorf("Validate(%q, skew %d) = %d, %v", tt.code, tt.skew, step, ok)
		}
	}
}

func TestURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	u, err := url.Parse(URI("My App", "ana@example.com", secret))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if u.Scheme != "otpauth" || u.Host != "totp" || q.Get("secret") != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" ||
		q.Get("issuer") != "My App" || q.Get("digits") != "6" || q.Get("period") != "30" || q.Get("algorithm") != "SHA1" ||
		!strings.Contains(u.Path, "My App:ana@example.com") {
		t.Fatalf("uri = %s", u)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes := NewRecoveryCodes()
	if len(codes) != RecoveryCodeCount || len(hashes) != RecoveryCodeCount {
		t.Fatalf("%d codes, %d hashes", len(codes), len(hashes))
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 11 || c[5] != '-' || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		typed := strings.ToUpper(strings.ReplaceAll(c, "-", " "))
		if !bytes.Equal(HashRecoveryCode(typed), hashes[i]) {
			t.Fatalf("%q does not match its hash when typed as %q", c, typed)
		}
	}
}
