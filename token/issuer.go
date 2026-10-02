package token

import "context"

// Claims represents the canonical (normalized) claims embedded in an access token.
//
// These claims are format-agnostic and stable.
type Claims struct {
	SubjectID string            // internal subject identifier
	Roles     []string          // optional coarse-grained roles
	Attrs     map[string]string // optional attributes (org, tier, etc)
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
	//
	// TODO:
	//   - Audience support
	//   - Scope / permission embedding
	//   - Key rotation strategies, Token versioning
	Issue(
		ctx context.Context,
		claims Claims,
	) (string, error)
}
