package google

import (
	"context"
	"errors"
	"fmt"

	"github.com/kararnab/iam/provider"
	"google.golang.org/api/idtoken"
)

// Provider implements Google authentication via ID Token.
type Provider struct {
	clientID string
}

// New creates a Google auth provider.
//
// clientID = OAuth client ID issued by Google
func New(clientID string) *Provider {
	return &Provider{clientID: clientID}
}

func (p *Provider) Name() string {
	return "google"
}

// Authenticate verifies a Google ID token.
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

	payload, err := idtoken.Validate(ctx, rawToken, p.clientID)
	if err != nil {
		return nil, fmt.Errorf("google: %w", provider.ErrInvalidCredentials)
	}

	sub, ok := payload.Claims["sub"].(string)
	if !ok {
		return nil, errors.New("google token missing sub")
	}

	email, _ := payload.Claims["email"].(string)
	name, _ := payload.Claims["name"].(string)
	verified, _ := payload.Claims["email_verified"].(bool)

	return &provider.Identity{
		Provider:      p.Name(),
		ProviderID:    sub, // stable Google user ID
		Email:         email,
		EmailVerified: verified,
		DisplayName:   name,
		Attrs: map[string]string{
			"email": email,
			"name":  name,
		},
	}, nil
}
