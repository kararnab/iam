package jwt

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

// Issuer issues JWT access tokens signed with the provider's active key.
//
// The active key is read on every call, so rotating the provider takes
// effect for the next token issued.
type Issuer struct {
	keys keys.Provider
	cfg  Config
}

var _ token.Issuer = (*Issuer)(nil)

// NewIssuer creates a JWT issuer. The provider's current active key must be
// valid for signing.
func NewIssuer(kp keys.Provider, cfg Config) (*Issuer, error) {
	if kp == nil {
		return nil, errors.New("jwt: key provider is required")
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	if err := kp.ActiveKey().ValidateForJWT(true); err != nil {
		return nil, err
	}
	return &Issuer{keys: kp, cfg: cfg}, nil
}

// Issue implements token.Issuer.
func (i *Issuer) Issue(
	ctx context.Context,
	claims token.Claims,
) (string, error) {

	if claims.SubjectID == "" {
		return "", errors.New("jwt: subject is required")
	}

	k := i.keys.ActiveKey()
	if err := k.ValidateForJWT(true); err != nil {
		return "", err
	}

	now := i.cfg.Now().Unix()

	h, err := json.Marshal(header{Alg: string(k.Alg), Kid: k.ID, Typ: TokenType})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(payload{
		Iss:   i.cfg.Issuer,
		Sub:   claims.SubjectID,
		Aud:   audience{i.cfg.Audience},
		Iat:   now,
		Nbf:   now,
		Exp:   now + int64(i.cfg.TTL.Seconds()),
		Jti:   rand.Text(),
		Sid:   claims.SessionID,
		Roles: claims.Roles,
		Attrs: claims.Attrs,
	})
	if err != nil {
		return "", err
	}

	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig, err := sign(k, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}
