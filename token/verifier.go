package token

import "context"

// Verifier is responsible for validating access tokens
// and extracting embedded claims.
//
// Implementations must:
//   - validate token integrity
//   - validate expiry
//   - extract normalized claims
type Verifier interface {

	// Verify validates an access token and returns its claims.
	//
	// TODO:
	//   - Support multiple token formats simultaneously
	//   - Key rotation / grace periods
	//   - Optional introspection fallback
	Verify(
		ctx context.Context,
		accessToken string,
	) (*Claims, error)
}
