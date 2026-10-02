package paseto

import (
	"context"
	"errors"
	"time"

	"github.com/o1egl/paseto"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

// KeySize is the required symmetric key length.
const KeySize = 32

// Issuer implements token.Issuer using PASETO v2.local.
//
// Tokens are encrypted (not signed). The provider's active key is read on
// every call, so rotation takes effect immediately.
//
// TODO (P8): move to PASETO v4 with a maintained library.
type Issuer struct {
	paseto *paseto.V2
	keys   keys.Provider
	issuer string
	ttl    time.Duration
}

// NewIssuer creates a PASETO v2.local issuer. The active key's Secret must be
// KeySize bytes.
func NewIssuer(
	kp keys.Provider,
	issuer string,
	ttl time.Duration,
) (*Issuer, error) {

	if kp == nil {
		return nil, errors.New("paseto: key provider is required")
	}
	if len(kp.ActiveKey().Secret) != KeySize {
		return nil, errors.New("paseto: key must be 32 bytes")
	}

	return &Issuer{
		paseto: paseto.NewV2(),
		keys:   kp,
		issuer: issuer,
		ttl:    ttl,
	}, nil
}

// Issue implements token.Issuer.
func (i *Issuer) Issue(
	ctx context.Context,
	claims token.Claims,
) (string, error) {

	k := i.keys.ActiveKey()
	if len(k.Secret) != KeySize {
		return "", errors.New("paseto: key must be 32 bytes")
	}

	now := time.Now()

	payload := map[string]any{
		"iss": i.issuer,
		"sub": claims.SubjectID,
		"iat": now.Unix(),
		"exp": now.Add(i.ttl).Unix(),
	}

	if claims.SessionID != "" {
		payload["sid"] = claims.SessionID
	}
	if len(claims.Roles) > 0 {
		payload["roles"] = claims.Roles
	}
	if len(claims.Attrs) > 0 {
		payload["attrs"] = claims.Attrs
	}

	// The key ID goes in the (authenticated, unencrypted) footer.
	return i.paseto.Encrypt(k.Secret, payload, k.ID)
}
