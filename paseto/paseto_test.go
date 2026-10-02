package paseto

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

func key(id, fill string) keys.Key {
	return keys.Key{ID: id, Secret: []byte(strings.Repeat(fill, KeySize))}
}

func TestIssueVerify(t *testing.T) {
	ctx := context.Background()
	kp := keys.NewMemoryProvider(key("p1", "a"))
	iss, err := NewIssuer(kp, "iss", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ver := NewVerifier(kp, "iss")

	tok, err := iss.Issue(ctx, token.Claims{SubjectID: "u", SessionID: "s", Roles: []string{"admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := kp.Rotate(key("p2", "b")); err != nil {
		t.Fatal(err)
	}
	tok2, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})

	expired, _ := (&Issuer{paseto: iss.paseto, keys: kp, issuer: "iss", ttl: -time.Hour}).Issue(ctx, token.Claims{SubjectID: "u"})
	otherIss, _ := NewIssuer(kp, "other", time.Minute)
	wrongIssuer, _ := otherIss.Issue(ctx, token.Claims{SubjectID: "u"})
	strangers := keys.NewMemoryProvider(key("p2", "c"))
	forgedIss, _ := NewIssuer(strangers, "iss", time.Minute)
	forged, _ := forgedIss.Issue(ctx, token.Claims{SubjectID: "u"})

	tests := []struct {
		name    string
		tok     string
		ok      bool
		expired bool
	}{
		{"old key", tok, true, false},
		{"rotated key", tok2, true, false},
		{"expired", expired, false, true},
		{"wrong issuer", wrongIssuer, false, false},
		{"same kid, different secret", forged, false, false},
		{"garbage", "v2.local.abc", false, false},
		{"empty", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ver.Verify(ctx, tt.tok)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, token.ErrInvalidToken) {
				t.Fatalf("err %v does not wrap ErrInvalidToken", err)
			}
			if errors.Is(err, token.ErrExpiredToken) != tt.expired {
				t.Fatalf("expired mismatch: %v", err)
			}
			if tt.ok && c.SubjectID != "u" {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
}

func TestNewIssuerRejectsShortKey(t *testing.T) {
	if _, err := NewIssuer(keys.NewMemoryProvider(keys.Key{ID: "x", Secret: []byte("short")}), "i", time.Minute); err == nil {
		t.Fatal("short key accepted")
	}
}
