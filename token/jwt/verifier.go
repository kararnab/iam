package jwt

import (
	"context"
	"errors"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"github.com/kararnab/iam/token"
)

// Verifier verifies JWT access tokens using a single key.
type Verifier struct {
	Issuer string
}

// NewVerifier creates a JWT verifier.
func NewVerifier(
	issuer string,
) *Verifier {
	return &Verifier{
		Issuer: issuer,
	}
}

// VerifyWithKey verifies a JWT using the provided signing key.
func (v *Verifier) VerifyWithKey(
	ctx context.Context,
	accessToken string,
	key []byte,
) (*token.Claims, error) {

	parsed, err := jwtlib.Parse(
		accessToken,
		func(t *jwtlib.Token) (any, error) {
			if _, ok := t.Method.(*jwtlib.SigningMethodHMAC); !ok {
				return nil, errors.New("jwt: unexpected signing method")
			}
			return key, nil
		},
		// jwtlib.WithAudience(nil), // audience optional for MVP
		jwtlib.WithIssuer(v.Issuer),
	)
	if err != nil || !parsed.Valid {
		return nil, errors.New("jwt: invalid token")
	}

	claimsMap, ok := parsed.Claims.(jwtlib.MapClaims)
	if !ok {
		return nil, errors.New("jwt: invalid claims")
	}

	// Expiry check (defensive)
	if exp, ok := claimsMap["exp"].(float64); ok {
		if time.Now().After(time.Unix(int64(exp), 0)) {
			return nil, errors.New("jwt: token expired")
		}
	}

	sub, _ := claimsMap["sub"].(string)

	// Optional roles
	var roles []string
	if r, ok := claimsMap["roles"].([]any); ok {
		for _, v := range r {
			if s, ok := v.(string); ok {
				roles = append(roles, s)
			}
		}
	}

	// Optional attrs
	attrs := make(map[string]string)
	if a, ok := claimsMap["attrs"].(map[string]any); ok {
		for k, v := range a {
			if s, ok := v.(string); ok {
				attrs[k] = s
			}
		}
	}

	return &token.Claims{
		SubjectID: sub,
		Roles:     roles,
		Attrs:     attrs,
	}, nil
}
