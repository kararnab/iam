package paseto

import (
	"context"
	"errors"
	"fmt"
	"strings"

	pasetolib "aidanwoods.dev/go-paseto"

	"github.com/kararnab/iam/v2/token"
	"github.com/kararnab/iam/v2/token/keys"
)

// Verifier implements token.Verifier for v4.local and v4.public tokens.
//
// The token's header ("v4.local." or "v4.public.") must match the
// algorithm pinned on the key named in the footer.
type Verifier struct {
	keys keys.Provider
	cfg  Config
}

var _ token.Verifier = (*Verifier)(nil)

// NewVerifier returns a PASETO v4 verifier.
func NewVerifier(kp keys.Provider, cfg Config) (*Verifier, error) {
	if kp == nil {
		return nil, errors.New("paseto: key provider is required")
	}
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	return &Verifier{keys: kp, cfg: cfg}, nil
}

func invalid(msg string) error {
	return fmt.Errorf("%w: paseto: %s", token.ErrInvalidToken, msg)
}

// Verify implements token.Verifier.
func (v *Verifier) Verify(ctx context.Context, tainted string) (*token.Claims, error) {
	if len(tainted) > MaxTokenSize {
		return nil, invalid("token too large")
	}

	var protocol pasetolib.Protocol
	var alg keys.Alg
	switch {
	case strings.HasPrefix(tainted, "v4.local."):
		protocol, alg = pasetolib.V4Local, V4Local
	case strings.HasPrefix(tainted, "v4.public."):
		protocol, alg = pasetolib.V4Public, V4Public
	default:
		return nil, invalid("unsupported version or purpose")
	}

	// The footer is authenticated later by decryption or verification.
	parser := pasetolib.NewParserWithoutExpiryCheck()
	kid, err := parser.UnsafeParseFooter(protocol, tainted)
	if err != nil || len(kid) == 0 {
		return nil, invalid("missing key id")
	}
	k, ok := keys.Find(v.keys, string(kid))
	if !ok || k.Alg != alg || validate(k, false) != nil {
		return nil, invalid("unknown key")
	}

	var t *pasetolib.Token
	switch alg {
	case V4Local:
		sk, kerr := pasetolib.V4SymmetricKeyFromBytes(k.Secret)
		if kerr != nil {
			return nil, invalid("unusable key")
		}
		t, err = parser.ParseV4Local(sk, tainted, nil)
	case V4Public:
		pk, kerr := pasetolib.NewV4AsymmetricPublicKeyFromEd25519(k.PublicKey)
		if kerr != nil {
			return nil, invalid("unusable key")
		}
		t, err = parser.ParseV4Public(pk, tainted, nil)
	}
	if err != nil {
		return nil, invalid("authentication failed")
	}

	return v.claims(t)
}

func (v *Verifier) claims(t *pasetolib.Token) (*token.Claims, error) {
	now := v.cfg.Now()
	leeway := v.cfg.Leeway

	iss, err1 := t.GetIssuer()
	aud, err2 := t.GetAudience()
	sub, err3 := t.GetSubject()
	exp, err4 := t.GetExpiration()
	iat, err5 := t.GetIssuedAt()
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return nil, invalid("missing claims")
	}

	switch {
	case iss != v.cfg.Issuer:
		return nil, invalid("wrong issuer")
	case aud != v.cfg.Audience:
		return nil, invalid("wrong audience")
	case sub == "":
		return nil, invalid("missing subject")
	case now.After(exp.Add(leeway)):
		return nil, fmt.Errorf("%w: %w", token.ErrInvalidToken, token.ErrExpiredToken)
	case now.Add(leeway).Before(iat):
		return nil, invalid("issued in the future")
	}
	if nbf, err := t.GetNotBefore(); err == nil && now.Add(leeway).Before(nbf) {
		return nil, invalid("not yet valid")
	}

	c := &token.Claims{
		SubjectID: sub,
		Issuer:    iss,
		Audience:  aud,
		IssuedAt:  iat,
		ExpiresAt: exp,
	}
	c.ID, _ = t.GetJti()
	c.SessionID, _ = t.GetString("sid")
	_ = t.Get("roles", &c.Roles)
	_ = t.Get("attrs", &c.Attrs)
	return c, nil
}
