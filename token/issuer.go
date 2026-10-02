package token

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrInvalidToken is returned (wrapped) for any token that fails parsing,
	// signature or claim validation. Callers should not distinguish further
	// in responses to clients.
	ErrInvalidToken = errors.New("token: invalid")

	// ErrExpiredToken is returned (wrapped together with ErrInvalidToken)
	// when the token is well-formed and authentic but past its expiry.
	ErrExpiredToken = errors.New("token: expired")
)

// Claims represents the canonical (normalized) claims embedded in an access token.
//
// These claims are format-agnostic and stable. Fields marked "set by issuer"
// are ignored on input to Issue and filled in on output from Verify.
type Claims struct {
	SubjectID string            // internal subject identifier
	SessionID string            // public session identifier ("sid"), optional
	Roles     []string          // optional coarse-grained roles
	Attrs     map[string]string // optional attributes (org, tier, etc)

	ID        string    // unique token ID ("jti"), set by issuer
	Issuer    string    // set by issuer
	Audience  string    // set by issuer
	IssuedAt  time.Time // set by issuer
	ExpiresAt time.Time // set by issuer
}

// Issuer is responsible for minting/issuing access tokens.
//
// An Issuer:
//   - signs tokens
//   - embeds claims
//   - controls expiry
//
// An Issuer MUST NOT:
//   - validate refresh tokens
//   - talk to identity providers
//   - know about HTTP or transport
//
// Implementations may be JWT, PASETO, or opaque tokens.
type Issuer interface {

	// Issue generates a signed or encrypted access token.
	Issue(
		ctx context.Context,
		claims Claims,
	) (string, error)
}
