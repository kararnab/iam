package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kararnab/iam/provider"
)

// Provider implements OIDC authentication via OIDC ID Token.
// Can be used by Keyclock, Google OAuth, or any other OIDC providers
type Provider struct {
	verifier *oidc.IDTokenVerifier
}

// New creates a OIDC auth provider.
//
// issuerURL = e.g. https://keycloak.example.com/realms/myrealm
// clientID  = OIDC client ID
func New(ctx context.Context, issuerURL, clientID string) (*Provider, error) {
	prov, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, err
	}

	verifier := prov.Verifier(&oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: true, // Google quirk
	})

	return &Provider{verifier: verifier}, nil
}

func (p *Provider) Name() string {
	return "generic-oidc"
}

// Authenticate verifies an OIDC ID token.
//
// Expected params:
//   - "id_token"
func (p *Provider) Authenticate(
	ctx context.Context,
	params map[string]string,
) (*provider.Identity, error) {

	rawToken, ok := params["id_token"]
	if !ok || rawToken == "" {
		return nil, errors.New("missing id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", provider.ErrInvalidCredentials)
	}

	var claims struct {
		Sub               string `json:"sub"`
		Email             string `json:"email"`
		EmailVerified     bool   `json:"email_verified"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.New("failed to parse keycloak claims")
	}

	if claims.Sub == "" {
		return nil, errors.New("keycloak token missing sub")
	}

	return &provider.Identity{
		Provider:      p.Name(),
		ProviderID:    claims.Sub, // stable Keycloak user ID
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   claims.Name,
		Attrs: map[string]string{
			"email":    claims.Email,
			"name":     claims.Name,
			"username": claims.PreferredUsername,
		},
	}, nil
}
