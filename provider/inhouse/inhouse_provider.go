package inhouse

import (
	"context"
	"errors"
	"time"

	"github.com/kararnab/iam/provider"

	"golang.org/x/crypto/bcrypt"
)

// User represents the minimum user record required
// for internal username/password authentication.
type User struct {
	ID         string
	Provider   string // internal | google | keycloak
	ProviderID string // google sub / keycloak sub / internal id
	Email      string
	Name       string
	Roles      []string
	CreatedAt  time.Time

	PasswordHash string
}

// UserStore abstracts user lookup for the internal provider.
//
// This is intentionally minimal and defined here to avoid
// leaking application-specific user models into IAM.
type UserStore interface {
	GetByUsername(
		ctx context.Context,
		username string,
	) (*User, error)

	Create(
		ctx context.Context,
		user *User,
	) error
}

// Provider implements username/password authentication.
//
// It satisfies provider.AuthProvider.
type Provider struct {
	users UserStore
}

// New creates a new internal authentication provider.
func New(users UserStore) *Provider {
	return &Provider{users: users}
}

// Name returns the provider identifier used in AuthRequest.Provider.
func (p *Provider) Name() string {
	return "internal"
}

// Authenticate validates username/password credentials.
//
// Expected params:
//   - "username"
//   - "password"
func (p *Provider) Authenticate(
	ctx context.Context,
	params map[string]string,
) (*provider.Identity, error) {

	username, ok := params["username"]
	if !ok || username == "" {
		return nil, errors.New("missing username")
	}

	password, ok := params["password"]
	if !ok || password == "" {
		return nil, errors.New("missing password")
	}

	user, err := p.users.GetByUsername(ctx, username)
	if err != nil {
		// Do NOT leak whether username exists
		return nil, errors.New("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.PasswordHash),
		[]byte(password),
	); err != nil {
		return nil, errors.New("invalid credentials")
	}

	return &provider.Identity{
		Provider:   p.Name(),
		ProviderID: user.ID,
		Roles:      user.Roles,
		Attrs: map[string]string{
			"email": user.Email,
		},
	}, nil
}
