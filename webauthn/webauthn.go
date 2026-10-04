// Package webauthn adds passkeys and security keys (WebAuthn) to iam, as an
// identity provider.
//
// Each registered credential is an identity of its subject (provider
// "passkey", provider ID = the base64url credential ID), linked through
// your iam.IdentityStore. Signing in is an ordinary iam.Service.Login with
// this provider, so throttling, audit and sessions work as for passwords:
//
//	opts, state, _ := pk.BeginLogin(ctx)            // to navigator.credentials.get()
//	res, err := svc.Login(ctx, iam.AuthRequest{
//	    Provider: pk.Name(),
//	    Params:   map[string]string{"state": state, "response": string(assertionJSON)},
//	})
//
// Ceremonies are verified by github.com/go-webauthn/webauthn. Their state
// (the challenge) is sealed with AES-GCM into an opaque string, so no
// server-side store is needed.
package webauthn

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/passkey"
	"github.com/kararnab/iam/v2/provider"
)

// DefaultName is the default provider name.
const DefaultName = "passkey"

var (
	// ErrInvalidState is returned when a ceremony's state is missing,
	// tampered with, expired, of the wrong kind, or for another subject.
	ErrInvalidState = errors.New("webauthn: ceremony state is invalid or expired")

	// ErrRegistration is returned when an authenticator's registration
	// response does not verify.
	ErrRegistration = errors.New("webauthn: registration failed")
)

// Config configures a Provider.
type Config struct {
	// Name is the provider name, in iam.AuthRequest.Provider and in linked
	// identities. Default "passkey". It must stay stable once identities are
	// linked.
	Name string

	// RPID is the relying party ID: your site's registrable domain, for
	// example "example.com". Credentials are bound to it.
	RPID string

	// RPDisplayName is shown by the browser during registration.
	RPDisplayName string

	// RPOrigins are the exact origins allowed to run ceremonies, for example
	// "https://app.example.com".
	RPOrigins []string

	// Credentials stores the registered credentials.
	Credentials passkey.Store

	// Identities links each credential to its subject. Use the same store
	// as iam.Config.Users.
	Identities iam.IdentityStore

	// Key seals ceremony state; at least 32 bytes. Give every instance the
	// same key.
	Key []byte

	// Timeout bounds a ceremony. Default 5 minutes, max 15 minutes.
	Timeout time.Duration

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// Provider runs WebAuthn ceremonies and implements provider.AuthProvider.
type Provider struct {
	name       string
	w          *gowebauthn.WebAuthn
	creds      passkey.Store
	identities iam.IdentityStore
	aead       cipher.AEAD
	timeout    time.Duration
	now        func() time.Time
}

var _ provider.AuthProvider = (*Provider)(nil)

// New validates cfg and returns a provider.
func New(cfg Config) (*Provider, error) {
	if cfg.Credentials == nil || cfg.Identities == nil {
		return nil, errors.New("webauthn: Credentials and Identities are required")
	}
	if cfg.RPID == "" || cfg.RPDisplayName == "" || len(cfg.RPOrigins) == 0 {
		return nil, errors.New("webauthn: RPID, RPDisplayName and RPOrigins are required")
	}
	if len(cfg.Key) < 32 {
		return nil, errors.New("webauthn: Key must be at least 32 bytes")
	}
	if cfg.Name == "" {
		cfg.Name = DefaultName
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	if cfg.Timeout < 0 || cfg.Timeout > 15*time.Minute {
		return nil, errors.New("webauthn: Timeout must be between 0 and 15 minutes")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	w, err := gowebauthn.New(&gowebauthn.Config{
		RPID:          cfg.RPID,
		RPDisplayName: cfg.RPDisplayName,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
		AttestationPreference: protocol.PreferNoAttestation,
		Timeouts: gowebauthn.TimeoutsConfig{
			Login:        gowebauthn.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout},
			Registration: gowebauthn.TimeoutConfig{Enforce: true, Timeout: cfg.Timeout, TimeoutUVD: cfg.Timeout},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: %w", err)
	}

	mac := hmac.New(sha256.New, cfg.Key)
	mac.Write([]byte("iam-webauthn-state-v1:" + cfg.Name))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Provider{
		name: cfg.Name, w: w, creds: cfg.Credentials, identities: cfg.Identities,
		aead: aead, timeout: cfg.Timeout, now: cfg.Now,
	}, nil
}

// Name implements provider.AuthProvider.
func (p *Provider) Name() string { return p.name }

// ProviderID returns the identity's provider ID for a credential ID.
func ProviderID(credentialID []byte) string {
	return base64.RawURLEncoding.EncodeToString(credentialID)
}

// ---------------------------------------------------------------------------
// Ceremony state
// ---------------------------------------------------------------------------

const (
	kindLogin    = "login"
	kindRegister = "register"
)

type state struct {
	Kind      string                 `json:"k"`
	SubjectID string                 `json:"s,omitempty"`
	Expires   int64                  `json:"e"`
	Session   gowebauthn.SessionData `json:"d"`
}

func (p *Provider) seal(st state) (string, error) {
	plain, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, p.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return base64.RawURLEncoding.EncodeToString(p.aead.Seal(nonce, nonce, plain, []byte(st.Kind))), nil
}

func (p *Provider) open(s, kind string) (*state, error) {
	if len(s) > 8192 {
		return nil, ErrInvalidState
	}
	sealed, err := base64.RawURLEncoding.DecodeString(s)
	n := p.aead.NonceSize()
	if err != nil || len(sealed) < n {
		return nil, ErrInvalidState
	}
	plain, err := p.aead.Open(nil, sealed[:n], sealed[n:], []byte(kind))
	if err != nil {
		return nil, ErrInvalidState
	}
	var st state
	if json.Unmarshal(plain, &st) != nil || st.Kind != kind || !p.now().Before(time.Unix(st.Expires, 0)) {
		return nil, ErrInvalidState
	}
	return &st, nil
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

// User describes the subject registering a credential. Name is shown by the
// authenticator to pick an account (usually the email); DisplayName
// defaults to Name.
type User struct {
	SubjectID   string
	Name        string
	DisplayName string
}

// user adapts a subject to go-webauthn.
type user struct {
	id, name, display string
	creds             []gowebauthn.Credential
}

func (u *user) WebAuthnID() []byte                           { return []byte(u.id) }
func (u *user) WebAuthnName() string                         { return u.name }
func (u *user) WebAuthnDisplayName() string                  { return u.display }
func (u *user) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

func toLibrary(c *passkey.Credential) gowebauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return gowebauthn.Credential{
		ID:                c.ID,
		PublicKey:         c.PublicKey,
		AttestationType:   c.AttestationType,
		AttestationFormat: c.AttestationFormat,
		Transport:         transports,
		Flags: gowebauthn.CredentialFlags{
			UserPresent: c.UserPresent, UserVerified: c.UserVerified,
			BackupEligible: c.BackupEligible, BackupState: c.BackupState,
		},
		Authenticator: gowebauthn.Authenticator{AAGUID: c.AAGUID, SignCount: c.SignCount},
	}
}

// BeginRegistration starts adding a credential for a signed-in subject. It
// returns the options for navigator.credentials.create() (JSON, with a
// "publicKey" member) and a state to send back to FinishRegistration. The
// subject's existing credentials are excluded, so an authenticator is not
// registered twice. Authorize the caller first.
func (p *Provider) BeginRegistration(ctx context.Context, u User) (options []byte, st string, err error) {
	if u.SubjectID == "" || u.Name == "" {
		return nil, "", errors.New("webauthn: SubjectID and Name are required")
	}
	existing, err := p.creds.ListBySubject(ctx, u.SubjectID)
	if err != nil {
		return nil, "", err
	}
	if u.DisplayName == "" {
		u.DisplayName = u.Name
	}
	wu := &user{id: u.SubjectID, name: u.Name, display: u.DisplayName}
	exclude := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		lc := toLibrary(c)
		exclude = append(exclude, lc.Descriptor())
	}
	creation, session, err := p.w.BeginRegistration(wu, gowebauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: %w", err)
	}
	st, err = p.seal(state{Kind: kindRegister, SubjectID: u.SubjectID, Expires: p.now().Add(p.timeout).Unix(), Session: *session})
	if err != nil {
		return nil, "", err
	}
	options, err = json.Marshal(creation)
	return options, st, err
}

// FinishRegistration verifies the authenticator's response (the JSON of
// the PublicKeyCredential from navigator.credentials.create()), stores the
// credential under name, and links it to the subject as an identity.
// subjectID must be the subject that began the ceremony.
func (p *Provider) FinishRegistration(ctx context.Context, subjectID, st string, response []byte, name string) (*passkey.Credential, error) {
	s, err := p.open(st, kindRegister)
	if err != nil || s.SubjectID != subjectID {
		return nil, ErrInvalidState
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistration, err)
	}
	wu := &user{id: subjectID}
	lc, err := p.w.CreateCredential(wu, s.Session, parsed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRegistration, err)
	}

	transports := make([]string, len(lc.Transport))
	for i, t := range lc.Transport {
		transports[i] = string(t)
	}
	c := &passkey.Credential{
		ID: lc.ID, SubjectID: subjectID, Name: strings.TrimSpace(name),
		PublicKey: lc.PublicKey, AttestationType: lc.AttestationType, AttestationFormat: lc.AttestationFormat,
		AAGUID: lc.Authenticator.AAGUID, Transports: transports, SignCount: lc.Authenticator.SignCount,
		UserPresent: lc.Flags.UserPresent, UserVerified: lc.Flags.UserVerified,
		BackupEligible: lc.Flags.BackupEligible, BackupState: lc.Flags.BackupState,
		CreatedAt: p.now(),
	}
	if err := p.creds.Create(ctx, c); err != nil {
		return nil, err
	}
	if err := p.identities.LinkIdentity(ctx, subjectID, provider.Identity{Provider: p.name, ProviderID: ProviderID(c.ID)}); err != nil {
		_ = p.creds.Delete(ctx, subjectID, c.ID)
		return nil, err
	}
	return c, nil
}

// Credentials lists a subject's registered credentials.
func (p *Provider) Credentials(ctx context.Context, subjectID string) ([]*passkey.Credential, error) {
	return p.creds.ListBySubject(ctx, subjectID)
}

// RemoveCredential deletes one of the subject's credentials and unlinks its
// identity. Authorize the caller first (and consider keeping at least one
// way to sign in).
func (p *Provider) RemoveCredential(ctx context.Context, subjectID string, credentialID []byte) error {
	if err := p.identities.UnlinkIdentity(ctx, subjectID, p.name, ProviderID(credentialID)); err != nil {
		return err
	}
	return p.creds.Delete(ctx, subjectID, credentialID)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

// BeginLogin starts a passkey sign-in without a username (discoverable
// credentials). It returns the options for navigator.credentials.get() and
// a state; send both back through iam.Service.Login with this provider.
func (p *Provider) BeginLogin(_ context.Context) (options []byte, st string, err error) {
	assertion, session, err := p.w.BeginDiscoverableLogin()
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: %w", err)
	}
	st, err = p.seal(state{Kind: kindLogin, Expires: p.now().Add(p.timeout).Unix(), Session: *session})
	if err != nil {
		return nil, "", err
	}
	options, err = json.Marshal(assertion)
	return options, st, err
}

func invalid() error { return fmt.Errorf("webauthn: %w", provider.ErrInvalidCredentials) }

// Authenticate implements provider.AuthProvider. Params: "state" from
// BeginLogin and "response", the JSON of the PublicKeyCredential from
// navigator.credentials.get(). The authenticator must have verified the
// user (PIN or biometrics), and a signature counter that went backwards
// (a cloned authenticator) is rejected.
func (p *Provider) Authenticate(ctx context.Context, params map[string]string) (*provider.Identity, error) {
	s, err := p.open(params["state"], kindLogin)
	if err != nil {
		return nil, invalid()
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes([]byte(params["response"]))
	if err != nil {
		return nil, invalid()
	}

	var stored *passkey.Credential
	var storeErr error
	handler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		c, err := p.creds.Get(ctx, rawID)
		if err != nil {
			if !errors.Is(err, passkey.ErrNotFound) {
				storeErr = err
			}
			return nil, err
		}
		if c.SubjectID != string(userHandle) {
			return nil, errors.New("webauthn: user handle does not match the credential")
		}
		stored = c
		return &user{id: c.SubjectID, creds: []gowebauthn.Credential{toLibrary(c)}}, nil
	}
	_, lc, err := p.w.ValidatePasskeyLogin(handler, s.Session, parsed)
	if storeErr != nil {
		return nil, fmt.Errorf("webauthn: credential lookup: %w", storeErr)
	}
	if err != nil || stored == nil {
		return nil, invalid()
	}
	if lc.Authenticator.CloneWarning {
		return nil, invalid()
	}
	if err := p.creds.Touch(ctx, stored.ID, lc.Authenticator.SignCount, lc.Flags.BackupState, p.now()); err != nil {
		return nil, fmt.Errorf("webauthn: record sign-in: %w", err)
	}
	return &provider.Identity{
		Provider:   p.name,
		ProviderID: ProviderID(stored.ID),
		Attrs:      map[string]string{"credential_name": stored.Name},
	}, nil
}
