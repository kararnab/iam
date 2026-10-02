package provider

import "context"

// Identity represents a verified external identity returned by an
// authentication provider.
//
// This is NOT exposed outside IAM.
// It is an intermediate representation used to:
//   - normalize identities
//   - map external users to internal subjects
type Identity struct {
	Provider    string            // e.g. "google", "keycloak", "internal"
	ProviderID  string            // stable external identifier (sub, user_id)
	Email       string            // optional, provider-dependent
	DisplayName string            // optional, provider-dependent
	Roles       []string          // optional, provider-dependent
	Attrs       map[string]string // raw provider attributes (claims, metadata)
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
	// a verified external identity.
	//
	// The meaning of params is provider-specific.
	//
	// Expected behavior:
	//   - Validate credentials or assertions
	//   - Verify signatures / tokens if applicable
	//   - Return a stable ProviderID
	//
	// TODO:
	//   - Support partial auth (MFA pending)
	//   - Step-up / challenge responses
	//   - Provider-specific error mapping
	Authenticate(
		ctx context.Context,
		params map[string]string,
	) (*Identity, error)
}
