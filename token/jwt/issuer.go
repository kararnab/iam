package jwt

import (
	"context"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/kararnab/iam/token"
)

// Issuer issues JWT access tokens using a single signing key.
type Issuer struct {
	key    []byte
	keyID  string // kid
	issuer string
	ttl    time.Duration
}

// NewIssuer creates a JWT issuer.
//
// keyID is embedded as "kid" in JWT header (for rotation).
func NewIssuer(
	key []byte,
	keyID string,
	issuer string,
	ttl time.Duration,
) *Issuer {
	return &Issuer{
		key:    key,
		keyID:  keyID,
		issuer: issuer,
		ttl:    ttl,
	}
}

// Issue implements token.Issuer.
func (i *Issuer) Issue(
	ctx context.Context,
	claims token.Claims,
) (string, error) {

	now := time.Now()

	jwtClaims := jwtlib.MapClaims{
		"iss": i.issuer,
		"sub": claims.SubjectID,
		"iat": now.Unix(),
		"exp": now.Add(i.ttl).Unix(),
	}

	if len(claims.Roles) > 0 {
		jwtClaims["roles"] = claims.Roles
	}
	if len(claims.Attrs) > 0 {
		jwtClaims["attrs"] = claims.Attrs
	}

	t := jwtlib.NewWithClaims(
		jwtlib.SigningMethodHS256,
		jwtClaims,
	)

	// 🔑 Key rotation support
	t.Header["kid"] = i.keyID

	return t.SignedString(i.key)
}
