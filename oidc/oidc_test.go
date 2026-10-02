package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/kararnab/iam/v2/provider"
)

// fakeIssuer serves discovery and JWKS and signs ID tokens.
type fakeIssuer struct {
	srv *httptest.Server
	key *rsa.PrivateKey
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"jwks_uri":                              f.srv.URL + "/jwks",
			"authorization_endpoint":                f.srv.URL + "/auth",
			"token_endpoint":                        f.srv.URL + "/token",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "k1").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	obj, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *fakeIssuer) claims(mutate func(map[string]any)) map[string]any {
	now := time.Now()
	c := map[string]any{
		"iss": f.srv.URL, "aud": "client-1", "sub": "user-123",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"email": "u@example.com", "email_verified": true, "name": "U", "nonce": "n-1",
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()
	f := newFakeIssuer(t)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	strict, err := New(ctx, Config{Name: "corp", IssuerURL: f.srv.URL, ClientID: "client-1", RequireNonce: true})
	if err != nil {
		t.Fatal(err)
	}
	multi, err := New(ctx, Config{IssuerURL: f.srv.URL, ClientID: "client-1", AdditionalIssuers: []string{"alt-issuer"}})
	if err != nil {
		t.Fatal(err)
	}

	set := func(k string, v any) func(map[string]any) { return func(c map[string]any) { c[k] = v } }
	tests := []struct {
		name   string
		prov   *Provider
		token  string
		nonce  string
		ok     bool
		verify func(*provider.Identity) bool
	}{
		{"valid", strict, f.sign(t, f.key, f.claims(nil)), "n-1", true, func(id *provider.Identity) bool {
			return id.Provider == "corp" && id.ProviderID == "user-123" && id.Email == "u@example.com" && id.EmailVerified
		}},
		{"email_verified as string", strict, f.sign(t, f.key, f.claims(set("email_verified", "true"))), "n-1", true, func(id *provider.Identity) bool { return id.EmailVerified }},
		{"unverified email", strict, f.sign(t, f.key, f.claims(set("email_verified", false))), "n-1", true, func(id *provider.Identity) bool { return !id.EmailVerified }},
		{"missing nonce param when required", strict, f.sign(t, f.key, f.claims(nil)), "", false, nil},
		{"nonce mismatch", strict, f.sign(t, f.key, f.claims(nil)), "n-2", false, nil},
		{"wrong audience", strict, f.sign(t, f.key, f.claims(set("aud", "someone-else"))), "n-1", false, nil},
		{"wrong issuer", strict, f.sign(t, f.key, f.claims(set("iss", "https://evil.example"))), "n-1", false, nil},
		{"expired", strict, f.sign(t, f.key, f.claims(set("exp", time.Now().Add(-time.Hour).Unix()))), "n-1", false, nil},
		{"signed by an unknown key", strict, f.sign(t, otherKey, f.claims(nil)), "n-1", false, nil},
		{"empty subject", strict, f.sign(t, f.key, f.claims(set("sub", ""))), "n-1", false, nil},
		{"empty token", strict, "", "n-1", false, nil},
		{"garbage", strict, "a.b.c", "n-1", false, nil},
		{"additional issuer accepted", multi, f.sign(t, f.key, f.claims(set("iss", "alt-issuer"))), "", true, nil},
		{"primary issuer accepted", multi, f.sign(t, f.key, f.claims(nil)), "", true, nil},
		{"other issuer still rejected", multi, f.sign(t, f.key, f.claims(set("iss", "https://evil.example"))), "", false, nil},
		{"nonce optional but checked if given", multi, f.sign(t, f.key, f.claims(nil)), "wrong", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]string{"id_token": tt.token}
			if tt.nonce != "" {
				params["nonce"] = tt.nonce
			}
			id, err := tt.prov.Authenticate(ctx, params)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok=%v", err, tt.ok)
			}
			if err != nil && !errors.Is(err, provider.ErrInvalidCredentials) {
				t.Fatalf("err %v does not wrap ErrInvalidCredentials", err)
			}
			if tt.verify != nil && !tt.verify(id) {
				t.Fatalf("identity = %+v", id)
			}
		})
	}
}

func TestNewValidates(t *testing.T) {
	ctx := context.Background()
	if _, err := New(ctx, Config{ClientID: "c"}); err == nil {
		t.Fatal("missing issuer accepted")
	}
	if _, err := New(ctx, Config{IssuerURL: "http://127.0.0.1:1", ClientID: "c"}); err == nil {
		t.Fatal("unreachable issuer accepted")
	}
}
