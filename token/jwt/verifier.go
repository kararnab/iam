package jwt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

// Verifier verifies JWT access tokens.
//
// Checks, in order: size and shape, header ("typ" must be at+jwt, "kid" must
// name a known key, "alg" must equal that key's pinned algorithm), signature,
// then claims ("iss", "aud", "exp", "nbf", "iat" with leeway, non-empty "sub").
type Verifier struct {
	keys keys.Provider
	cfg  Config
}

var _ token.Verifier = (*Verifier)(nil)

// NewVerifier creates a JWT verifier.
func NewVerifier(kp keys.Provider, cfg Config) (*Verifier, error) {
	if kp == nil {
		return nil, errors.New("jwt: key provider is required")
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	return &Verifier{keys: kp, cfg: cfg}, nil
}

// Verify implements token.Verifier.
func (v *Verifier) Verify(
	ctx context.Context,
	accessToken string,
) (*token.Claims, error) {

	hdrJSON, body, sig, input, err := split(accessToken)
	if err != nil {
		return nil, err
	}

	var h header
	dec := json.NewDecoder(bytes.NewReader(hdrJSON))
	dec.DisallowUnknownFields() // rejects "crit", "jku", "x5u", embedded keys, ...
	if err := dec.Decode(&h); err != nil || dec.More() {
		return nil, invalid("bad header")
	}
	if !isAccessTokenType(h.Typ) {
		return nil, invalid("wrong token type")
	}
	if h.Kid == "" {
		return nil, invalid("missing kid")
	}

	k, ok := keys.Find(v.keys, h.Kid)
	if !ok {
		return nil, invalid("unknown key")
	}
	if err := k.ValidateForJWT(false); err != nil {
		return nil, invalid("unusable key")
	}
	if h.Alg != string(k.Alg) {
		return nil, invalid("algorithm mismatch")
	}
	if !verifySignature(k, []byte(input), sig) {
		return nil, invalid("bad signature")
	}

	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, invalid("bad payload")
	}

	now := v.cfg.Now()
	leeway := v.cfg.Leeway

	switch {
	case p.Iss != v.cfg.Issuer:
		return nil, invalid("wrong issuer")
	case !p.Aud.contains(v.cfg.Audience):
		return nil, invalid("wrong audience")
	case p.Sub == "":
		return nil, invalid("missing subject")
	case p.Exp == 0 || p.Iat == 0:
		return nil, invalid("missing exp or iat")
	case now.After(time.Unix(p.Exp, 0).Add(leeway)):
		return nil, fmt.Errorf("%w: %w", token.ErrInvalidToken, token.ErrExpiredToken)
	case p.Nbf != 0 && now.Add(leeway).Before(time.Unix(p.Nbf, 0)):
		return nil, invalid("not yet valid")
	case now.Add(leeway).Before(time.Unix(p.Iat, 0)):
		return nil, invalid("issued in the future")
	}

	return &token.Claims{
		SubjectID: p.Sub,
		SessionID: p.Sid,
		Roles:     p.Roles,
		Attrs:     p.Attrs,
		ID:        p.Jti,
		Issuer:    p.Iss,
		Audience:  v.cfg.Audience,
		IssuedAt:  time.Unix(p.Iat, 0),
		ExpiresAt: time.Unix(p.Exp, 0),
	}, nil
}

// isAccessTokenType accepts "at+jwt" and "application/at+jwt" (RFC 9068 §2.1),
// case-insensitively.
func isAccessTokenType(typ string) bool {
	typ = strings.ToLower(typ)
	return typ == TokenType || typ == "application/"+TokenType
}
