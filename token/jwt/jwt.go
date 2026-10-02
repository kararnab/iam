// Package jwt issues and verifies JWT access tokens (RFC 7519, RFC 9068)
// using only the standard library.
//
// Only two algorithms exist: HS256 and EdDSA (Ed25519). Every key is pinned
// to one algorithm through keys.Key.Alg, and the verifier looks the key up by
// "kid" and requires the token's "alg" to match it. "none", RSA and ECDSA are
// never accepted, which rules out algorithm-confusion attacks by construction.
package jwt

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/keys"
)

const (
	// DefaultTTL is the access-token lifetime when Config.TTL is zero.
	DefaultTTL = 10 * time.Minute

	// DefaultLeeway is the clock-skew allowance when Config.Leeway is zero.
	DefaultLeeway = 30 * time.Second

	// MaxLeeway caps Config.Leeway.
	MaxLeeway = 2 * time.Minute

	// MaxTokenSize is the largest token the verifier will parse.
	MaxTokenSize = 8 << 10

	// TokenType is the "typ" header for access tokens (RFC 9068).
	TokenType = "at+jwt"
)

// Config holds the settings shared by Issuer and Verifier.
type Config struct {
	Issuer   string        // "iss"; required
	Audience string        // "aud"; required
	TTL      time.Duration // issuer only; DefaultTTL if zero
	Leeway   time.Duration // verifier only; DefaultLeeway if zero, at most MaxLeeway

	// Now returns the current time. Nil means time.Now. Useful in tests.
	Now func() time.Time
}

func (c Config) normalize() (Config, error) {
	if c.Issuer == "" {
		return c, errors.New("jwt: Config.Issuer is required")
	}
	if c.Audience == "" {
		return c, errors.New("jwt: Config.Audience is required")
	}
	if c.TTL < 0 || c.Leeway < 0 {
		return c, errors.New("jwt: TTL and Leeway must not be negative")
	}
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	if c.Leeway == 0 {
		c.Leeway = DefaultLeeway
	}
	if c.Leeway > MaxLeeway {
		return c, fmt.Errorf("jwt: Leeway must be at most %s", MaxLeeway)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c, nil
}

type header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type payload struct {
	Iss   string            `json:"iss"`
	Sub   string            `json:"sub"`
	Aud   audience          `json:"aud"`
	Exp   int64             `json:"exp"`
	Nbf   int64             `json:"nbf"`
	Iat   int64             `json:"iat"`
	Jti   string            `json:"jti"`
	Sid   string            `json:"sid,omitempty"`
	Roles []string          `json:"roles,omitempty"`
	Attrs map[string]string `json:"attrs,omitempty"`
}

// audience accepts both forms allowed by RFC 7519: a string or an array.
type audience []string

func (a audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

func (a *audience) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*a = audience{s}
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	*a = list
	return nil
}

func (a audience) contains(v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}

var b64 = base64.RawURLEncoding.Strict()

// sign returns the signature over input with k, which must already be validated.
func sign(k keys.Key, input []byte) ([]byte, error) {
	switch k.Alg {
	case keys.HS256:
		m := hmac.New(sha256.New, k.Secret)
		m.Write(input)
		return m.Sum(nil), nil
	case keys.EdDSA:
		return ed25519.Sign(k.PrivateKey, input), nil
	default:
		return nil, fmt.Errorf("jwt: unsupported algorithm %q", k.Alg)
	}
}

// verifySignature checks sig over input with k, in constant time for HMAC.
func verifySignature(k keys.Key, input, sig []byte) bool {
	switch k.Alg {
	case keys.HS256:
		m := hmac.New(sha256.New, k.Secret)
		m.Write(input)
		return hmac.Equal(m.Sum(nil), sig)
	case keys.EdDSA:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.PublicKey, input, sig)
	default:
		return false
	}
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{token.ErrInvalidToken}, args...)...)
}

// split breaks a compact JWS into its three decoded parts and signing input.
func split(tok string) (hdr, body, sig []byte, input string, err error) {
	if len(tok) > MaxTokenSize {
		return nil, nil, nil, "", invalid("token too large")
	}
	if strings.Count(tok, ".") != 2 {
		return nil, nil, nil, "", invalid("malformed")
	}
	parts := strings.SplitN(tok, ".", 3)
	if hdr, err = b64.DecodeString(parts[0]); err != nil {
		return nil, nil, nil, "", invalid("malformed header")
	}
	if body, err = b64.DecodeString(parts[1]); err != nil {
		return nil, nil, nil, "", invalid("malformed payload")
	}
	if sig, err = b64.DecodeString(parts[2]); err != nil {
		return nil, nil, nil, "", invalid("malformed signature")
	}
	return hdr, body, sig, parts[0] + "." + parts[1], nil
}
