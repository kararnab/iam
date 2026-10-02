// Package paseto issues and verifies PASETO v4 access tokens
// (aidanwoods.dev/go-paseto).
//
//   - keys.Alg "v4.local": symmetric, encrypted tokens (Secret, 32 bytes).
//     Only services holding the key can read or mint tokens.
//   - keys.Alg "v4.public": Ed25519-signed tokens (PrivateKey to issue,
//     PublicKey to verify). Readable by anyone; verifiable without the
//     signing key.
//
// The key ID travels in the footer, which is authenticated in both modes.
package paseto

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	pasetolib "aidanwoods.dev/go-paseto"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

const (
	// V4Local selects encrypted v4.local tokens.
	V4Local keys.Alg = "v4.local"

	// V4Public selects Ed25519-signed v4.public tokens.
	V4Public keys.Alg = "v4.public"

	// KeySize is the v4.local key length.
	KeySize = 32

	// DefaultTTL, DefaultLeeway and MaxLeeway match the JWT package.
	DefaultTTL    = 10 * time.Minute
	DefaultLeeway = 30 * time.Second
	MaxLeeway     = 2 * time.Minute

	// MaxTokenSize is the largest token the verifier will parse.
	MaxTokenSize = 8 << 10
)

// Config holds the settings shared by Issuer and Verifier.
type Config struct {
	Issuer   string        // required
	Audience string        // required
	TTL      time.Duration // issuer only; DefaultTTL if zero
	Leeway   time.Duration // verifier only; DefaultLeeway if zero

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

func (c Config) normalize() (Config, error) {
	if c.Issuer == "" || c.Audience == "" {
		return c, errors.New("paseto: Issuer and Audience are required")
	}
	if c.TTL < 0 || c.Leeway < 0 || c.Leeway > MaxLeeway {
		return c, fmt.Errorf("paseto: TTL must not be negative and Leeway must be within [0, %s]", MaxLeeway)
	}
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	if c.Leeway == 0 {
		c.Leeway = DefaultLeeway
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}

// validate checks that k is usable for alg (sign: issuing).
func validate(k keys.Key, sign bool) error {
	if k.ID == "" {
		return errors.New("paseto: key ID is required")
	}
	switch k.Alg {
	case V4Local:
		if len(k.Secret) != KeySize {
			return fmt.Errorf("paseto: v4.local key %q must be %d bytes", k.ID, KeySize)
		}
	case V4Public:
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("paseto: v4.public key %q has no valid public key", k.ID)
		}
		if sign && len(k.PrivateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("paseto: v4.public key %q has no valid private key", k.ID)
		}
	default:
		return fmt.Errorf("paseto: key %q has unsupported algorithm %q", k.ID, k.Alg)
	}
	return nil
}

// Issuer implements token.Issuer. The provider's active key is read on
// every call, so rotation takes effect immediately.
type Issuer struct {
	keys keys.Provider
	cfg  Config
}

var _ token.Issuer = (*Issuer)(nil)

// NewIssuer returns a PASETO v4 issuer.
func NewIssuer(kp keys.Provider, cfg Config) (*Issuer, error) {
	if kp == nil {
		return nil, errors.New("paseto: key provider is required")
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if err := validate(kp.ActiveKey(), true); err != nil {
		return nil, err
	}
	return &Issuer{keys: kp, cfg: cfg}, nil
}

// Issue implements token.Issuer.
func (i *Issuer) Issue(ctx context.Context, claims token.Claims) (string, error) {
	if claims.SubjectID == "" {
		return "", errors.New("paseto: subject is required")
	}
	k := i.keys.ActiveKey()
	if err := validate(k, true); err != nil {
		return "", err
	}

	now := i.cfg.Now()
	t := pasetolib.NewToken()
	t.SetIssuer(i.cfg.Issuer)
	t.SetAudience(i.cfg.Audience)
	t.SetSubject(claims.SubjectID)
	t.SetIssuedAt(now)
	t.SetNotBefore(now)
	t.SetExpiration(now.Add(i.cfg.TTL))
	t.SetJti(rand.Text())
	if claims.SessionID != "" {
		t.SetString("sid", claims.SessionID)
	}
	if len(claims.Roles) > 0 {
		if err := t.Set("roles", claims.Roles); err != nil {
			return "", err
		}
	}
	if len(claims.Attrs) > 0 {
		if err := t.Set("attrs", claims.Attrs); err != nil {
			return "", err
		}
	}
	t.SetFooter([]byte(k.ID))

	switch k.Alg {
	case V4Local:
		sk, err := pasetolib.V4SymmetricKeyFromBytes(k.Secret)
		if err != nil {
			return "", err
		}
		return t.V4Encrypt(sk, nil), nil
	default: // V4Public, checked by validate
		sk, err := pasetolib.NewV4AsymmetricSecretKeyFromEd25519(k.PrivateKey)
		if err != nil {
			return "", err
		}
		return t.V4Sign(sk, nil), nil
	}
}
