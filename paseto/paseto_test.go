package paseto

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kararnab/iam/v2/token"
	"github.com/kararnab/iam/v2/token/keys"
)

var (
	ctx = context.Background()
	t0  = time.Unix(1_800_000_000, 0)
)

func localKey(id, fill string) keys.Key {
	return keys.Key{ID: id, Alg: V4Local, Secret: []byte(strings.Repeat(fill, KeySize))}
}

func publicKey(id string) keys.Key {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return keys.Key{ID: id, Alg: V4Public, PrivateKey: priv, PublicKey: pub}
}

func cfgAt(now time.Time) Config {
	return Config{Issuer: "iss", Audience: "aud", TTL: time.Minute, Now: func() time.Time { return now }}
}

func issue(t *testing.T, kp keys.Provider, cfg Config, c token.Claims) string {
	t.Helper()
	i, err := NewIssuer(kp, cfg)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := i.Issue(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRoundTrip(t *testing.T) {
	for _, k := range []keys.Key{localKey("l1", "a"), publicKey("p1")} {
		t.Run(string(k.Alg), func(t *testing.T) {
			kp := keys.NewMemoryProvider(k)
			tok := issue(t, kp, cfgAt(t0), token.Claims{
				SubjectID: "u", SessionID: "s", Roles: []string{"admin"}, Attrs: map[string]string{"org": "acme"},
			})
			if !strings.HasPrefix(tok, string(k.Alg)+".") {
				t.Fatalf("token = %q", tok[:12])
			}
			v, _ := NewVerifier(kp, cfgAt(t0))
			c, err := v.Verify(ctx, tok)
			if err != nil {
				t.Fatal(err)
			}
			if c.SubjectID != "u" || c.SessionID != "s" || len(c.Roles) != 1 || c.Attrs["org"] != "acme" || c.ID == "" || c.Audience != "aud" {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	local := localKey("l1", "a")
	pub := publicKey("p1")
	kp := keys.NewMemoryProvider(local)
	if err := kp.Rotate(pub); err != nil {
		t.Fatal(err)
	}
	good := issue(t, keys.NewMemoryProvider(local), cfgAt(t0), token.Claims{SubjectID: "u"})

	// A v4.public token whose footer names the v4.local key: algorithm mismatch.
	mislabelled := issue(t, keys.NewMemoryProvider(keys.Key{ID: "l1", Alg: V4Public, PrivateKey: pub.PrivateKey, PublicKey: pub.PublicKey}), cfgAt(t0), token.Claims{SubjectID: "u"})
	otherSecret := issue(t, keys.NewMemoryProvider(localKey("l1", "b")), cfgAt(t0), token.Claims{SubjectID: "u"})
	unknownKid := issue(t, keys.NewMemoryProvider(localKey("zz", "a")), cfgAt(t0), token.Claims{SubjectID: "u"})
	wrongIss := issue(t, keys.NewMemoryProvider(local), Config{Issuer: "evil", Audience: "aud", Now: cfgAt(t0).Now}, token.Claims{SubjectID: "u"})
	wrongAud := issue(t, keys.NewMemoryProvider(local), Config{Issuer: "iss", Audience: "other", Now: cfgAt(t0).Now}, token.Claims{SubjectID: "u"})
	future := issue(t, keys.NewMemoryProvider(local), cfgAt(t0.Add(time.Hour)), token.Claims{SubjectID: "u"})

	tests := []struct {
		name    string
		tok     string
		now     time.Time
		expired bool
	}{
		{"v2 token", "v2.local.abc", t0, false},
		{"v3 token", "v3.public.abc", t0, false},
		{"garbage", "v4.local.!!!", t0, false},
		{"empty", "", t0, false},
		{"too large", "v4.local." + strings.Repeat("a", MaxTokenSize), t0, false},
		{"algorithm mismatch", mislabelled, t0, false},
		{"wrong secret, same kid", otherSecret, t0, false},
		{"unknown kid", unknownKid, t0, false},
		{"tampered", good[:len(good)-12] + "AAAA" + good[len(good)-8:], t0, false},
		{"wrong issuer", wrongIss, t0, false},
		{"wrong audience", wrongAud, t0, false},
		{"expired beyond leeway", good, t0.Add(time.Minute + DefaultLeeway + time.Second), true},
		{"issued in the future", future, t0, false},
	}
	v, _ := NewVerifier(kp, cfgAt(t0))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v.cfg.Now = func() time.Time { return tt.now }
			_, err := v.Verify(ctx, tt.tok)
			if !errors.Is(err, token.ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
			if errors.Is(err, token.ErrExpiredToken) != tt.expired {
				t.Fatalf("expired mismatch: %v", err)
			}
		})
	}

	v.cfg.Now = func() time.Time { return t0.Add(time.Minute + DefaultLeeway) }
	if _, err := v.Verify(ctx, good); err != nil {
		t.Fatalf("within leeway: %v", err)
	}
}

func TestRotation(t *testing.T) {
	kp := keys.NewMemoryProvider(localKey("l1", "a"))
	iss, _ := NewIssuer(kp, cfgAt(t0))
	v, _ := NewVerifier(kp, cfgAt(t0))
	old, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})
	_ = kp.Rotate(localKey("l2", "b"))
	fresh, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})
	for name, tok := range map[string]string{"old": old, "new": fresh} {
		if _, err := v.Verify(ctx, tok); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	kp.Prune(0)
	if _, err := v.Verify(ctx, old); err == nil {
		t.Fatal("token from a pruned key verified")
	}
}

func TestConfigAndKeyValidation(t *testing.T) {
	pub := publicKey("p")
	tests := []struct {
		name string
		key  keys.Key
		cfg  Config
	}{
		{"short local key", keys.Key{ID: "x", Alg: V4Local, Secret: []byte("short")}, cfgAt(t0)},
		{"no alg", keys.Key{ID: "x", Secret: make([]byte, KeySize)}, cfgAt(t0)},
		{"JWT alg", keys.Key{ID: "x", Alg: keys.HS256, Secret: make([]byte, KeySize)}, cfgAt(t0)},
		{"public without private key", keys.Key{ID: "x", Alg: V4Public, PublicKey: pub.PublicKey}, cfgAt(t0)},
		{"missing issuer", localKey("x", "a"), Config{Audience: "a"}},
		{"leeway too large", localKey("x", "a"), Config{Issuer: "i", Audience: "a", Leeway: time.Hour}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewIssuer(keys.NewMemoryProvider(tt.key), tt.cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func FuzzVerify(f *testing.F) {
	kp := keys.NewMemoryProvider(localKey("l1", "a"))
	iss, _ := NewIssuer(kp, cfgAt(t0))
	v, _ := NewVerifier(kp, cfgAt(t0))
	good, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})
	f.Add(good)
	f.Add("v4.local.")
	f.Add("v4.public.AAAA.bDE")
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := v.Verify(ctx, tok)
		if err == nil && c.SubjectID != "u" {
			t.Fatalf("unexpected token verified: %q", tok)
		}
		if err != nil && !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("error does not wrap ErrInvalidToken: %v", err)
		}
	})
}
