package metrics

// IAMMetrics captures security-relevant counters.
//
// High-cardinality data MUST NOT be included.
// No user IDs, No tokens, No provider strings (can be added later as labels if needed)
type IAMMetrics interface {
	AuthSuccess()
	AuthFailure()

	TokenVerifySuccess()
	TokenVerifyFailure()

	TokenRefreshSuccess()
	TokenRefreshFailure()

	SessionRevokeSuccess()
	SessionRevokeFailure()

	PolicyDenied()
}
