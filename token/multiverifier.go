package token

import (
	"context"
	"errors"

	"github.com/kararnab/iam/token/keys"
)

// SingleVerifier verifies a token using ONE key.
type SingleVerifier interface {
	VerifyWithKey(
		ctx context.Context,
		accessToken string,
		key []byte,
	) (*Claims, error)
}

// MultiVerifier tries multiple keys for verification.
type MultiVerifier struct {
	Verifier    SingleVerifier
	KeyProvider keys.Provider
}

// Verify tries verification using all available keys.
func (m *MultiVerifier) Verify(
	ctx context.Context,
	accessToken string,
) (*Claims, error) {

	for _, k := range m.KeyProvider.VerificationKeys() {
		claims, err := m.Verifier.VerifyWithKey(ctx, accessToken, k.Key)
		if err == nil {
			return claims, nil
		}
	}

	return nil, errors.New("token verification failed")
}
