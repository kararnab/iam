package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

var (
	hsKey = keys.Key{ID: "hs-1", Alg: keys.HS256, Secret: []byte("0123456789abcdef0123456789abcdef")}
	edKey = func() keys.Key {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(err)
		}
		return keys.Key{ID: "ed-1", Alg: keys.EdDSA, PrivateKey: priv, PublicKey: pub}
	}()
	t0 = time.Unix(1_800_000_000, 0)
)

func cfgAt(now time.Time) Config {
	return Config{Issuer: "iss", Audience: "aud", TTL: time.Minute, Now: func() time.Time { return now }}
}

func mustIssuer(t *testing.T, kp keys.Provider, cfg Config) *Issuer {
	t.Helper()
	i, err := NewIssuer(kp, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func mustVerifier(t *testing.T, kp keys.Provider, cfg Config) *Verifier {
	t.Helper()
	v, err := NewVerifier(kp, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// forge builds a token from raw header and payload maps, signed with k.
func forge(t *testing.T, k keys.Key, hdr, body map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(hdr)
	p, _ := json.Marshal(body)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig, err := sign(k, []byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func unsigned(hdr, body map[string]any) string {
	h, _ := json.Marshal(hdr)
	p, _ := json.Marshal(body)
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p) + "."
}

func validBody() map[string]any {
	return map[string]any{
		"iss": "iss", "aud": "aud", "sub": "user-1",
		"iat": t0.Unix(), "nbf": t0.Unix(), "exp": t0.Add(time.Minute).Unix(), "jti": "j",
	}
}

func TestRoundTrip(t *testing.T) {
	for _, k := range []keys.Key{hsKey, edKey} {
		t.Run(string(k.Alg), func(t *testing.T) {
			kp := keys.NewMemoryProvider(k)
			in := token.Claims{
				SubjectID: "user-1", SessionID: "sess-1",
				Roles: []string{"admin"}, Attrs: map[string]string{"org": "acme"},
			}
			tok, err := mustIssuer(t, kp, cfgAt(t0)).Issue(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			got, err := mustVerifier(t, kp, cfgAt(t0)).Verify(context.Background(), tok)
			if err != nil {
				t.Fatal(err)
			}
			if got.SubjectID != "user-1" || got.SessionID != "sess-1" || len(got.Roles) != 1 ||
				got.Attrs["org"] != "acme" || got.ID == "" || got.Issuer != "iss" || got.Audience != "aud" ||
				!got.ExpiresAt.Equal(t0.Add(time.Minute)) {
				t.Fatalf("claims = %+v", got)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	kp := keys.NewMemoryProvider(hsKey)
	hdr := func(alg, kid, typ string) map[string]any {
		return map[string]any{"alg": alg, "kid": kid, "typ": typ}
	}
	with := func(k string, v any) map[string]any {
		b := validBody()
		if v == nil {
			delete(b, k)
		} else {
			b[k] = v
		}
		return b
	}
	otherHS := keys.Key{ID: "hs-1", Alg: keys.HS256, Secret: []byte("ffffffffffffffffffffffffffffffff")}
	good := forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), validBody())

	tests := []struct {
		name    string
		tok     string
		now     time.Time
		expired bool
	}{
		{"empty", "", t0, false},
		{"two parts", "a.b", t0, false},
		{"four parts", good + ".x", t0, false},
		{"padded base64", strings.Replace(good, ".", "=.", 1), t0, false},
		{"too large", strings.Repeat("a", MaxTokenSize+1), t0, false},
		{"alg none", unsigned(hdr("none", "hs-1", "at+jwt"), validBody()), t0, false},
		{"alg mismatch HS512", forge(t, hsKey, hdr("HS512", "hs-1", "at+jwt"), validBody()), t0, false},
		{"alg mismatch EdDSA", forge(t, hsKey, hdr("EdDSA", "hs-1", "at+jwt"), validBody()), t0, false},
		{"unknown kid", forge(t, hsKey, hdr("HS256", "nope", "at+jwt"), validBody()), t0, false},
		{"missing kid", forge(t, hsKey, hdr("HS256", "", "at+jwt"), validBody()), t0, false},
		{"typ JWT (e.g. an ID token)", forge(t, hsKey, hdr("HS256", "hs-1", "JWT"), validBody()), t0, false},
		{"crit header", forge(t, hsKey, map[string]any{"alg": "HS256", "kid": "hs-1", "typ": "at+jwt", "crit": []string{"x"}}, validBody()), t0, false},
		{"wrong secret", forge(t, otherHS, hdr("HS256", "hs-1", "at+jwt"), validBody()), t0, false},
		{"tampered payload", tamper(good), t0, false},
		{"wrong issuer", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("iss", "evil")), t0, false},
		{"wrong audience", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("aud", "other")), t0, false},
		{"missing audience", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("aud", nil)), t0, false},
		{"empty subject", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("sub", "")), t0, false},
		{"missing exp", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("exp", nil)), t0, false},
		{"float exp", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("exp", 1.9e9+0.5)), t0, false},
		{"expired beyond leeway", good, t0.Add(time.Minute + DefaultLeeway + time.Second), true},
		{"nbf in future", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("nbf", t0.Add(time.Hour).Unix())), t0, false},
		{"iat in future", forge(t, hsKey, hdr("HS256", "hs-1", "at+jwt"), with("iat", t0.Add(time.Hour).Unix())), t0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mustVerifier(t, kp, cfgAt(tt.now)).Verify(context.Background(), tt.tok)
			if !errors.Is(err, token.ErrInvalidToken) {
				t.Fatalf("err = %v, want ErrInvalidToken", err)
			}
			if errors.Is(err, token.ErrExpiredToken) != tt.expired {
				t.Fatalf("expired = %v, want %v", errors.Is(err, token.ErrExpiredToken), tt.expired)
			}
		})
	}
}

func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	body, _ := b64.DecodeString(parts[1])
	body = []byte(strings.Replace(string(body), `"user-1"`, `"admin1"`, 1))
	return parts[0] + "." + b64.EncodeToString(body) + "." + parts[2]
}

func TestLeewayBoundaries(t *testing.T) {
	kp := keys.NewMemoryProvider(hsKey)
	tok, err := mustIssuer(t, kp, cfgAt(t0)).Issue(context.Background(), token.Claims{SubjectID: "u"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"at exp", t0.Add(time.Minute), true},
		{"within leeway after exp", t0.Add(time.Minute + DefaultLeeway), true},
		{"past leeway", t0.Add(time.Minute + DefaultLeeway + time.Second), false},
		{"clock behind within leeway", t0.Add(-DefaultLeeway), true},
		{"clock behind past leeway", t0.Add(-DefaultLeeway - time.Second), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mustVerifier(t, kp, cfgAt(tt.now)).Verify(context.Background(), tok)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

// Regression for F11: the issuer must pick up rotated keys immediately.
func TestRotation(t *testing.T) {
	ctx := context.Background()
	kp := keys.NewMemoryProvider(hsKey)
	iss := mustIssuer(t, kp, cfgAt(t0))
	ver := mustVerifier(t, kp, cfgAt(t0))

	oldTok, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})
	k2 := keys.Key{ID: "hs-2", Alg: keys.HS256, Secret: []byte("22222222222222222222222222222222")}
	if err := kp.Rotate(k2); err != nil {
		t.Fatal(err)
	}
	if err := kp.Rotate(k2); err == nil {
		t.Fatal("duplicate key ID accepted")
	}
	newTok, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})

	if kidOf(t, newTok) != "hs-2" {
		t.Fatalf("issuer still signs with %q after rotation", kidOf(t, newTok))
	}
	for name, tok := range map[string]string{"old": oldTok, "new": newTok} {
		if _, err := ver.Verify(ctx, tok); err != nil {
			t.Fatalf("%s token: %v", name, err)
		}
	}
	kp.Prune(0)
	if _, err := ver.Verify(ctx, oldTok); err == nil {
		t.Fatal("token signed with pruned key still verifies")
	}
}

func kidOf(t *testing.T, tok string) string {
	t.Helper()
	h, _ := b64.DecodeString(strings.Split(tok, ".")[0])
	var hd header
	if err := json.Unmarshal(h, &hd); err != nil {
		t.Fatal(err)
	}
	return hd.Kid
}

func TestConfigAndKeyValidation(t *testing.T) {
	short := keys.Key{ID: "s", Alg: keys.HS256, Secret: []byte("dev-secret")}
	verifyOnly := keys.Key{ID: "v", Alg: keys.EdDSA, PublicKey: edKey.PublicKey}
	tests := []struct {
		name string
		key  keys.Key
		cfg  Config
	}{
		{"short HMAC key", short, cfgAt(t0)},
		{"no key ID", keys.Key{Alg: keys.HS256, Secret: hsKey.Secret}, cfgAt(t0)},
		{"unsupported alg", keys.Key{ID: "r", Alg: "RS256", Secret: hsKey.Secret}, cfgAt(t0)},
		{"EdDSA without private key", verifyOnly, cfgAt(t0)},
		{"missing issuer", hsKey, Config{Audience: "a"}},
		{"missing audience", hsKey, Config{Issuer: "i"}},
		{"leeway too large", hsKey, Config{Issuer: "i", Audience: "a", Leeway: time.Hour}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewIssuer(keys.NewMemoryProvider(tt.key), tt.cfg); err == nil {
				t.Fatal("NewIssuer accepted invalid input")
			}
		})
	}
	if _, err := NewVerifier(keys.NewMemoryProvider(verifyOnly), cfgAt(t0)); err != nil {
		t.Fatalf("verify-only EdDSA key rejected: %v", err)
	}
}

// RFC 7515 Appendix A.1 (HS256) and RFC 8037 Appendix A.4 (Ed25519) vectors
// check the signature primitives against independent implementations.
func TestRFCVectors(t *testing.T) {
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	t.Run("RFC7515 A.1 HS256", func(t *testing.T) {
		k := keys.Key{ID: "x", Alg: keys.HS256, Secret: dec("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")}
		input := "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
		sig := dec("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
		if !verifySignature(k, []byte(input), sig) {
			t.Fatal("RFC 7515 HS256 vector did not verify")
		}
	})
	t.Run("RFC8037 A.4 Ed25519", func(t *testing.T) {
		priv := ed25519.NewKeyFromSeed(dec("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"))
		pub := priv.Public().(ed25519.PublicKey)
		if b64.EncodeToString(pub) != "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" {
			t.Fatal("public key mismatch")
		}
		k := keys.Key{ID: "x", Alg: keys.EdDSA, PrivateKey: priv, PublicKey: pub}
		input := []byte("eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc")
		want := "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"
		got, _ := sign(k, input)
		if b64.EncodeToString(got) != want {
			t.Fatalf("signature = %s", b64.EncodeToString(got))
		}
		if !verifySignature(k, input, dec(want)) {
			t.Fatal("did not verify")
		}
	})
}

func FuzzVerify(f *testing.F) {
	kp := keys.NewMemoryProvider(hsKey)
	iss, _ := NewIssuer(kp, cfgAt(t0))
	ver, _ := NewVerifier(kp, cfgAt(t0))
	good, _ := iss.Issue(context.Background(), token.Claims{SubjectID: "u", Roles: []string{"r"}})
	f.Add(good)
	f.Add("")
	f.Add("..")
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add(tamper(good))

	f.Fuzz(func(t *testing.T, tok string) {
		claims, err := ver.Verify(context.Background(), tok)
		if err == nil {
			// Anything that verifies must carry exactly what our issuer signed.
			// (Fuzz workers re-run setup, so the seed token's jti differs per process.)
			if claims.SubjectID != "u" || len(claims.Roles) != 1 || claims.Roles[0] != "r" {
				t.Fatalf("unexpected token verified: %q", tok)
			}
		} else if !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("error does not wrap ErrInvalidToken: %v", err)
		}
	})
}
