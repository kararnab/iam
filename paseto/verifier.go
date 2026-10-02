package paseto

import (
	"context"
	"errors"
	"time"

	"github.com/o1egl/paseto"

	"github.com/kararnab/iam/token"
)

// Verifier verifies PASETO v2.local tokens using a single key.
type Verifier struct {
	paseto *paseto.V2
	issuer string
}

// NewVerifier creates a PASETO verifier.
func NewVerifier(
	issuer string,
) *Verifier {
	return &Verifier{
		paseto: paseto.NewV2(),
		issuer: issuer,
	}
}

// VerifyWithKey decrypts and verifies a PASETO token using the provided key.
func (v *Verifier) VerifyWithKey(
	ctx context.Context,
	accessToken string,
	key []byte,
) (*token.Claims, error) {

	var payload map[string]any

	if err := v.paseto.Decrypt(
		accessToken,
		key,
		&payload,
		nil,
	); err != nil {
		return nil, errors.New("paseto: invalid token")
	}

	iss, ok := payload["iss"].(string)
	if !ok || iss != v.issuer {
		return nil, errors.New("paseto: invalid issuer")
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		return nil, errors.New("paseto: missing exp")
	}
	if time.Now().After(time.Unix(int64(exp), 0)) {
		return nil, errors.New("paseto: token expired")
	}

	sub, ok := payload["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("paseto: missing subject")
	}

	// Optional roles
	var roles []string
	if r, ok := payload["roles"].([]any); ok {
		for _, v := range r {
			if s, ok := v.(string); ok {
				roles = append(roles, s)
			}
		}
	}

	// Optional attrs
	attrs := make(map[string]string)
	if a, ok := payload["attrs"].(map[string]any); ok {
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
