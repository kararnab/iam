package password

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/provider"
)

// ProviderName is the provider name used in iam.AuthRequest.Provider.
const ProviderName = "password"

// CredentialStore persists password hashes by login name. It is implemented
// by the application (see memstore for a reference implementation).
//
// Logins are normalized by the provider (trimmed, lower-cased) before they
// reach the store.
type CredentialStore interface {
	// GetCredential returns the encoded hash for login, or iam.ErrNotFound.
	GetCredential(ctx context.Context, login string) (encodedHash string, err error)

	// CreateCredential stores a new credential, or returns iam.ErrConflict.
	CreateCredential(ctx context.Context, login, encodedHash string) error

	// UpdateCredential replaces an existing hash (rehash, password change).
	UpdateCredential(ctx context.Context, login, encodedHash string) error

	// DeleteCredential removes a credential. Missing is not an error.
	DeleteCredential(ctx context.Context, login string) error
}

// Provider authenticates logins with passwords.
//
// Params for Authenticate and Register: "username" and "password".
// The identity's ProviderID is the normalized login, which the application
// links to a subject through iam.IdentityStore.
type Provider struct {
	creds  CredentialStore
	hasher Hasher
	policy Policy
	dummy  string // hash verified when the login does not exist
}

var _ provider.Registrar = (*Provider)(nil)

// NewProvider returns a password provider. A zero Policy means DefaultPolicy.
func NewProvider(creds CredentialStore, hasher Hasher, policy Policy) (*Provider, error) {
	if creds == nil || hasher == nil {
		return nil, errors.New("password: credential store and hasher are required")
	}
	if policy == (Policy{}) {
		policy = DefaultPolicy
	}
	// A real hash with the current parameters, so that unknown logins cost
	// the same time as known ones and do not reveal which logins exist.
	dummy, err := hasher.Hash(context.Background(), "iam-dummy-password-for-timing")
	if err != nil {
		return nil, err
	}
	return &Provider{creds: creds, hasher: hasher, policy: policy, dummy: dummy}, nil
}

// Name implements provider.AuthProvider.
func (p *Provider) Name() string { return ProviderName }

// NormalizeLogin trims spaces and lower-cases a login name.
func NormalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func invalidCredentials() error {
	return fmt.Errorf("password: %w", provider.ErrInvalidCredentials)
}

// Authenticate implements provider.AuthProvider.
func (p *Provider) Authenticate(ctx context.Context, params map[string]string) (*provider.Identity, error) {
	login := NormalizeLogin(params["username"])
	pw := params["password"]
	if login == "" || pw == "" || len(pw) > p.policy.MaxLength {
		return nil, invalidCredentials()
	}

	encoded, err := p.creds.GetCredential(ctx, login)
	if errors.Is(err, iam.ErrNotFound) {
		_, _ = p.hasher.Verify(ctx, pw, p.dummy)
		return nil, invalidCredentials()
	}
	if err != nil {
		return nil, fmt.Errorf("password: credential lookup: %w", err)
	}

	ok, err := p.hasher.Verify(ctx, pw, encoded)
	if err != nil && !errors.Is(err, ErrMalformedHash) {
		return nil, err
	}
	if !ok {
		return nil, invalidCredentials()
	}

	// Transparent migration (bcrypt -> argon2id, or raised parameters).
	// Failure here must not fail the login.
	if p.hasher.NeedsRehash(encoded) {
		if fresh, err := p.hasher.Hash(ctx, pw); err == nil {
			_ = p.creds.UpdateCredential(ctx, login, fresh)
		}
	}

	return identity(login), nil
}

// Register implements provider.Registrar. It returns an error wrapping
// ErrTooShort/ErrTooLong for policy violations and iam.ErrConflict if the
// login is taken.
func (p *Provider) Register(ctx context.Context, params map[string]string) (*provider.Identity, error) {
	login := NormalizeLogin(params["username"])
	if login == "" {
		return nil, errors.New("password: username is required")
	}
	pw := params["password"]
	if err := p.policy.Check(pw); err != nil {
		return nil, err
	}
	encoded, err := p.hasher.Hash(ctx, pw)
	if err != nil {
		return nil, err
	}
	if err := p.creds.CreateCredential(ctx, login, encoded); err != nil {
		return nil, err
	}
	return identity(login), nil
}

// Unregister implements provider.Registrar.
func (p *Provider) Unregister(ctx context.Context, providerID string) error {
	return p.creds.DeleteCredential(ctx, providerID)
}

func identity(login string) *provider.Identity {
	id := &provider.Identity{
		Provider:   ProviderName,
		ProviderID: login,
		Attrs:      map[string]string{"username": login},
	}
	if strings.Contains(login, "@") {
		id.Email = login // not verified: the provider never checks mailbox ownership
	}
	return id
}
