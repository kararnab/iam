// Package provider defines identity providers: components that verify
// credentials (a password, an OIDC ID token) and return a stable external
// Identity.
//
// Providers never create sessions, issue tokens or assign roles. IAM maps
// identities to the application's subjects. Built-in providers live in
// package password and in the oidc module.
package provider

import (
	"context"
	"errors"
)

// ErrInvalidCredentials is returned (wrapped) by providers when the
// credentials or assertion are wrong. It never says which part was wrong.
var ErrInvalidCredentials = errors.New("provider: invalid credentials")

// Identity represents a verified external identity returned by an
// authentication provider.
//
// This is NOT exposed outside IAM.
// It is an intermediate representation used to:
//   - normalize identities
//   - map external users to internal subjects
//
// Identities carry no roles: authorization data belongs to the application
// and is loaded through iam.SubjectLoader.
type Identity struct {
	Provider      string            // e.g. "google", "oidc", "password"
	ProviderID    string            // stable external identifier (sub, login)
	Email         string            // optional, provider-dependent
	EmailVerified bool              // true only if the provider asserts it
	DisplayName   string            // optional, provider-dependent
	Attrs         map[string]string // raw provider attributes (claims, metadata)
}

// AuthProvider defines the contract every identity provider must satisfy.
//
// Providers are responsible ONLY for:
//   - validating credentials
//   - proving identity
//
// Providers MUST NOT:
//   - issue access tokens
//   - create sessions
//   - enforce authorization
//   - know about internal roles or policies
type AuthProvider interface {

	// Name returns a stable identifier for the provider.
	// This value is used in AuthRequest.Provider.
	//
	// Examples:
	//   - "google"
	//   - "keycloak"
	//   - "internal"
	Name() string

	// Authenticate validates the authentication request and returns
	// a verified external identity. Failed credentials must return an error
	// wrapping ErrInvalidCredentials.
	//
	// The meaning of params is provider-specific.
	//
	// Expected behavior:
	//   - Validate credentials or assertions
	//   - Verify signatures / tokens if applicable
	//   - Return a stable ProviderID
	//
	// A second factor is not the provider's concern: IAM asks for it after
	// the provider succeeds (iam.MFA).
	Authenticate(
		ctx context.Context,
		params map[string]string,
	) (*Identity, error)
}

// Registrar is implemented by providers that can create new credentials,
// such as username/password. It is used for sign-up.
type Registrar interface {
	AuthProvider

	// Register validates and stores new credentials, returning the identity
	// they authenticate as.
	Register(ctx context.Context, params map[string]string) (*Identity, error)

	// Unregister removes credentials created by Register. IAM calls it to
	// roll back a sign-up that failed after Register succeeded.
	Unregister(ctx context.Context, providerID string) error
}

// PasswordSetter is implemented by providers whose secret can be replaced,
// such as username/password. It is used for password reset.
type PasswordSetter interface {
	AuthProvider

	// CheckPassword validates a new password against the provider's policy
	// without storing anything.
	CheckPassword(password string) error

	// SetPassword replaces the password of an existing login (providerID).
	// It checks the policy first.
	SetPassword(ctx context.Context, providerID, password string) error
}
