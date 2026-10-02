// Package oidc authenticates users with OpenID Connect ID tokens (Google,
// Keycloak, Auth0, Entra ID, ...).
//
// The provider verifies an ID token the client obtained from the identity
// provider: signature (keys from the issuer's discovery document), issuer,
// audience (your client ID), expiry, and, when supplied, the nonce.
//
// It does not run the authorization-code flow itself (redirects, PKCE,
// state); that is planned for a later version.
package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/kararnab/iam/provider"
)

// GoogleIssuer is Google's issuer URL.
const GoogleIssuer = "https://accounts.google.com"

// Config configures a provider.
type Config struct {
	// Name is the provider name used in iam.AuthRequest.Provider and in
	// linked identities. Default "oidc". It must stay stable once identities
	// are linked.
	Name string

	// IssuerURL is the issuer; its discovery document is fetched by New.
	IssuerURL string

	// ClientID is your OAuth client ID; tokens must be issued for it.
	ClientID string

	// AdditionalIssuers are other "iss" values accepted for this issuer's
	// keys, for providers that use more than one spelling (Google uses both
	// "https://accounts.google.com" and "accounts.google.com").
	AdditionalIssuers []string

	// RequireNonce rejects tokens unless params["nonce"] is set and matches.
	RequireNonce bool
}

// Provider implements provider.AuthProvider.
//
// Params for Authenticate:
//   - "id_token": the ID token (required)
//   - "nonce": the nonce your server generated for this sign-in and kept in
//     its own state. Never take it from the client request: a client-chosen
//     expected nonce protects nothing.
type Provider struct {
	name     string
	verifier *gooidc.IDTokenVerifier
	issuers  []string
	nonce    bool
}

var _ provider.AuthProvider = (*Provider)(nil)

// New discovers the issuer and returns a provider. ctx is used for discovery
// and for later key refreshes, so pass a long-lived context.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.IssuerURL == "" || cfg.ClientID == "" {
		return nil, errors.New("oidc: IssuerURL and ClientID are required")
	}
	if cfg.Name == "" {
		cfg.Name = "oidc"
	}
	op, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}

	// go-oidc checks a single issuer. When several spellings are accepted,
	// its check is replaced by the explicit list below, never dropped.
	return &Provider{
		name: cfg.Name,
		verifier: op.Verifier(&gooidc.Config{
			ClientID:        cfg.ClientID,
			SkipIssuerCheck: len(cfg.AdditionalIssuers) > 0,
		}),
		issuers: append([]string{cfg.IssuerURL}, cfg.AdditionalIssuers...),
		nonce:   cfg.RequireNonce,
	}, nil
}

// NewGoogle returns a provider named "google" for Google ID tokens.
func NewGoogle(ctx context.Context, clientID string) (*Provider, error) {
	return New(ctx, Config{
		Name:              "google",
		IssuerURL:         GoogleIssuer,
		ClientID:          clientID,
		AdditionalIssuers: []string{"accounts.google.com"},
	})
}

// Name implements provider.AuthProvider.
func (p *Provider) Name() string { return p.name }

func invalid() error { return fmt.Errorf("oidc: %w", provider.ErrInvalidCredentials) }

// Authenticate implements provider.AuthProvider.
func (p *Provider) Authenticate(ctx context.Context, params map[string]string) (*provider.Identity, error) {
	raw := params["id_token"]
	if raw == "" {
		return nil, invalid()
	}

	tok, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, invalid()
	}
	if !slices.Contains(p.issuers, tok.Issuer) {
		return nil, invalid()
	}

	want := params["nonce"]
	if p.nonce && want == "" {
		return nil, invalid()
	}
	if want != "" && subtle.ConstantTimeCompare([]byte(tok.Nonce), []byte(want)) != 1 {
		return nil, invalid()
	}

	var claims struct {
		Email             string `json:"email"`
		EmailVerified     any    `json:"email_verified"` // bool, or "true" from some providers
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := tok.Claims(&claims); err != nil {
		return nil, invalid()
	}
	if tok.Subject == "" {
		return nil, invalid()
	}

	return &provider.Identity{
		Provider:      p.name,
		ProviderID:    tok.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified == true || claims.EmailVerified == "true",
		DisplayName:   claims.Name,
		Attrs: map[string]string{
			"email":    claims.Email,
			"name":     claims.Name,
			"username": claims.PreferredUsername,
			"issuer":   tok.Issuer,
		},
	}, nil
}
