package paseto

import (
	"context"
	"fmt"
	"time"

	"github.com/o1egl/paseto"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

// Verifier verifies PASETO v2.local tokens. The key is selected by the key ID
// in the token footer; it implements token.Verifier.
type Verifier struct {
	paseto *paseto.V2
	keys   keys.Provider
	issuer string
}

var _ token.Verifier = (*Verifier)(nil)

// NewVerifier creates a PASETO verifier.
func NewVerifier(
	kp keys.Provider,
	issuer string,
) *Verifier {
	return &Verifier{
		paseto: paseto.NewV2(),
		keys:   kp,
		issuer: issuer,
	}
}

func invalid(msg string) error {
	return fmt.Errorf("%w: paseto: %s", token.ErrInvalidToken, msg)
}

// Verify implements token.Verifier.
func (v *Verifier) Verify(
	ctx context.Context,
	accessToken string,
) (*token.Claims, error) {

	var kid string
	if err := paseto.ParseFooter(accessToken, &kid); err != nil || kid == "" {
		return nil, invalid("missing key id")
	}
	k, ok := keys.Find(v.keys, kid)
	if !ok || len(k.Secret) != KeySize {
		return nil, invalid("unknown key")
	}

	var payload map[string]any
	var footer string
	if err := v.paseto.Decrypt(accessToken, k.Secret, &payload, &footer); err != nil {
		return nil, invalid("decryption failed")
	}

	iss, ok := payload["iss"].(string)
	if !ok || iss != v.issuer {
		return nil, invalid("wrong issuer")
	}

	exp, ok := payload["exp"].(float64)
	if !ok {
		return nil, invalid("missing exp")
	}
	if time.Now().After(time.Unix(int64(exp), 0)) {
		return nil, fmt.Errorf("%w: %w", token.ErrInvalidToken, token.ErrExpiredToken)
	}

	sub, ok := payload["sub"].(string)
	if !ok || sub == "" {
		return nil, invalid("missing subject")
	}
	sid, _ := payload["sid"].(string)

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
		SessionID: sid,
		Roles:     roles,
		Attrs:     attrs,
		Issuer:    iss,
		ExpiresAt: time.Unix(int64(exp), 0),
	}, nil
}
