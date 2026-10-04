package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kararnab/iam/v2/token"
	"github.com/kararnab/iam/v2/token/keys"
)

func newEdKey(t *testing.T, id string) keys.Key {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return keys.Key{ID: id, Alg: keys.EdDSA, PrivateKey: priv, PublicKey: pub}
}

func TestPublicJWKS(t *testing.T) {
	a, b := newEdKey(t, "ed-a"), newEdKey(t, "ed-b")
	kp := keys.NewMemoryProvider(a)
	_ = kp.Rotate(hsKey)
	_ = kp.Rotate(b)

	set := PublicJWKS(kp)
	if len(set.Keys) != 2 || set.Keys[0].Kid != "ed-b" || set.Keys[1].Kid != "ed-a" {
		t.Fatalf("keys = %+v", set.Keys)
	}
	j := set.Keys[0]
	if j.Kty != "OKP" || j.Crv != "Ed25519" || j.Alg != "EdDSA" || j.Use != "sig" ||
		j.X != base64.RawURLEncoding.EncodeToString(b.PublicKey) {
		t.Fatalf("jwk = %+v", j)
	}
	body, _ := json.Marshal(set)
	for _, secret := range [][]byte{hsKey.Secret, b.PrivateKey.Seed(), b.PrivateKey} {
		if strings.Contains(string(body), base64.RawURLEncoding.EncodeToString(secret)) || strings.Contains(string(body), string(secret)) {
			t.Fatal("the set leaks secret material")
		}
	}
	if empty, _ := json.Marshal(PublicJWKS(keys.NewMemoryProvider(hsKey))); string(empty) != `{"keys":[]}` {
		t.Fatalf("HS256-only set = %s", empty)
	}
}

func TestJWKSHandler(t *testing.T) {
	kp := keys.NewMemoryProvider(newEdKey(t, "ed-a"))
	h := JWKSHandler(kp, time.Minute)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/jwk-set+json" ||
		rec.Header().Get("Cache-Control") != "public, max-age=60" {
		t.Fatalf("response = %d %v", rec.Code, rec.Header())
	}
	_ = kp.Rotate(newEdKey(t, "ed-b"))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(rec.Body.String(), `"ed-b"`) {
		t.Fatalf("rotation not visible: %s", rec.Body)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", rec.Code)
	}
}

// jwksServer serves a key provider's JWKS and counts requests.
type jwksServer struct {
	srv   *httptest.Server
	hits  atomic.Int32
	fail  atomic.Bool
	extra atomic.Value // string: replaces the body when set
}

func newJWKSServer(t *testing.T, kp keys.Provider) *jwksServer {
	t.Helper()
	s := &jwksServer{}
	h := JWKSHandler(kp, time.Minute)
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		if s.fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		if body, _ := s.extra.Load().(string); body != "" {
			_, _ = w.Write([]byte(body))
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func TestRemoteKeysVerifyAndRotate(t *testing.T) {
	ctx := context.Background()
	issuerKeys := keys.NewMemoryProvider(newEdKey(t, "ed-a"))
	srv := newJWKSServer(t, issuerKeys)
	cfg := Config{Issuer: "auth", Audience: "api"}
	iss, err := NewIssuer(issuerKeys, cfg)
	if err != nil {
		t.Fatal(err)
	}

	remote, err := NewRemoteKeys(ctx, srv.srv.URL, RemoteKeysConfig{AllowHTTP: true, MinRefreshInterval: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if remote.ActiveKey().ID != "" {
		t.Fatal("remote keys can sign")
	}
	ver, err := NewVerifier(remote, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if i, err := NewIssuer(remote, cfg); err == nil {
		if _, err := i.Issue(ctx, token.Claims{SubjectID: "u"}); err == nil {
			t.Fatal("issued a token with remote keys")
		}
	}

	tok, _ := iss.Issue(ctx, token.Claims{SubjectID: "u"})
	if c, err := ver.Verify(ctx, tok); err != nil || c.SubjectID != "u" {
		t.Fatalf("verify = %+v, %v", c, err)
	}

	// The issuer rotates; the first token with the new kid fetches the set.
	_ = issuerKeys.Rotate(newEdKey(t, "ed-b"))
	time.Sleep(2 * time.Millisecond)
	tok2, _ := iss.Issue(ctx, token.Claims{SubjectID: "u2"})
	if c, err := ver.Verify(ctx, tok2); err != nil || c.SubjectID != "u2" {
		t.Fatalf("after rotation: %+v, %v", c, err)
	}
	if _, err := ver.Verify(ctx, tok); err != nil {
		t.Fatalf("old key still published: %v", err)
	}

	// An HS256 token is never accepted, whatever its kid.
	hsTok, _ := mustIssuerFrom(keys.NewMemoryProvider(keys.Key{ID: "ed-b", Alg: keys.HS256, Secret: hsKey.Secret}), cfg).Issue(ctx, token.Claims{SubjectID: "x"})
	if _, err := ver.Verify(ctx, hsTok); !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("HS256 token with an EdDSA kid = %v", err)
	}
}

func mustIssuerFrom(kp keys.Provider, cfg Config) *Issuer {
	i, err := NewIssuer(kp, cfg)
	if err != nil {
		panic(err)
	}
	return i
}

func TestRemoteKeysRateLimitsUnknownKids(t *testing.T) {
	ctx := context.Background()
	srv := newJWKSServer(t, keys.NewMemoryProvider(newEdKey(t, "ed-a")))
	remote, err := NewRemoteKeys(ctx, srv.srv.URL, RemoteKeysConfig{AllowHTTP: true, MinRefreshInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 50 {
		if _, ok := remote.FindKey("made-up-" + string(rune('a'+i%26))); ok {
			t.Fatal("found a made-up key")
		}
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("%d fetches for unknown kids, want 1 (the initial one)", n)
	}
}

func TestRemoteKeysKeepsSetOnFailure(t *testing.T) {
	ctx := context.Background()
	srv := newJWKSServer(t, keys.NewMemoryProvider(newEdKey(t, "ed-a")))
	remote, err := NewRemoteKeys(ctx, srv.srv.URL, RemoteKeysConfig{AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	srv.fail.Store(true)
	if err := remote.Refresh(ctx); err == nil {
		t.Fatal("refresh against a failing server succeeded")
	}
	if _, ok := remote.FindKey("ed-a"); !ok {
		t.Fatal("previous keys were dropped")
	}
	srv.fail.Store(false)
	srv.extra.Store(`{"keys":[]}`)
	if err := remote.Refresh(ctx); err == nil {
		t.Fatal("an empty set replaced the keys")
	}
	if _, ok := remote.FindKey("ed-a"); !ok {
		t.Fatal("previous keys were dropped by an empty set")
	}
}

func TestNewRemoteKeysValidates(t *testing.T) {
	ctx := context.Background()
	srv := newJWKSServer(t, keys.NewMemoryProvider(newEdKey(t, "ed-a")))
	for _, u := range []string{srv.srv.URL, "/jwks", "ftp://x/jwks", "https://"} {
		if _, err := NewRemoteKeys(ctx, u, RemoteKeysConfig{}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	srv.fail.Store(true)
	if _, err := NewRemoteKeys(ctx, srv.srv.URL, RemoteKeysConfig{AllowHTTP: true}); err == nil {
		t.Error("an unreachable set accepted at start-up")
	}
	srv.fail.Store(false)
	srv.extra.Store(strings.Repeat(" ", maxJWKSSize+1))
	if _, err := NewRemoteKeys(ctx, srv.srv.URL, RemoteKeysConfig{AllowHTTP: true}); err == nil {
		t.Error("an oversized set accepted")
	}
}

func TestParseJWKSFilters(t *testing.T) {
	x := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	body := `{"keys":[
		{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"ok"},
		{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"ok"},
		{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"enc","use":"enc"},
		{"kty":"OKP","crv":"Ed25519","x":"` + x + `","kid":"rs","alg":"RS256"},
		{"kty":"OKP","crv":"X25519","x":"` + x + `","kid":"x"},
		{"kty":"OKP","crv":"Ed25519","x":"short","kid":"bad-x"},
		{"kty":"OKP","crv":"Ed25519","x":"` + x + `"},
		{"kty":"oct","k":"c2VjcmV0","kid":"hmac","alg":"HS256"},
		{"kty":"RSA","n":"AQAB","e":"AQAB","kid":"rsa"}
	]}`
	got, err := parseJWKS([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "ok" || got[0].Alg != keys.EdDSA || len(got[0].Secret) != 0 {
		t.Fatalf("keys = %+v", got)
	}
	if _, err := parseJWKS([]byte("not json")); err == nil {
		t.Fatal("garbage accepted")
	}
}
