package token

import "context"

// Verifier is responsible for validating access tokens
// and extracting embedded claims.
//
// Implementations must:
//   - pin the expected algorithm per key (never trust the token header)
//   - validate token integrity
//   - validate issuer, audience and expiry
//   - extract normalized claims
//
// Errors should wrap ErrInvalidToken (and ErrExpiredToken when expired).
type Verifier interface {

	// Verify validates an access token and returns its claims.
	Verify(
		ctx context.Context,
		accessToken string,
	) (*Claims, error)
}
