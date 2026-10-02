package paseto

import (
	"context"
	"errors"
	"time"

	"github.com/o1egl/paseto"

	"github.com/kararnab/iam/token"
)

// Issuer implements token.Issuer using PASETO v2.local.
//
// Tokens are encrypted (not signed).
// Key rotation is supported via embedded key ID ("kid").
type Issuer struct {
	paseto *paseto.V2
	key    []byte
	keyID  string
	issuer string
	ttl    time.Duration
}

// NewIssuer creates a PASETO v2.local issuer.
//
// key MUST be 32 bytes.
//
// TODO (prod):
//   - Support v4.public
func NewIssuer(
	key []byte,
	keyID string,
	issuer string,
	ttl time.Duration,
) (*Issuer, error) {

	if len(key) != 32 {
		return nil, errors.New("paseto: key must be 32 bytes")
	}

	return &Issuer{
		paseto: paseto.NewV2(),
		key:    key,
		keyID:  keyID,
		issuer: issuer,
		ttl:    ttl,
	}, nil
}

// Issue implements token.Issuer.
func (i *Issuer) Issue(
	ctx context.Context,
	claims token.Claims,
) (string, error) {

	now := time.Now()

	payload := map[string]any{
		"iss": i.issuer,
		"sub": claims.SubjectID,
		"iat": now.Unix(),
		"exp": now.Add(i.ttl).Unix(),

		// 🔑 Key rotation support
		"kid": i.keyID,
	}

	if len(claims.Roles) > 0 {
		payload["roles"] = claims.Roles
	}
	if len(claims.Attrs) > 0 {
		payload["attrs"] = claims.Attrs
	}

	tkn, err := i.paseto.Encrypt(i.key, payload, nil)
	if err != nil {
		return "", err
	}

	return tkn, nil
}
