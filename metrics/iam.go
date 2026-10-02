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

// Noop discards all metrics. It is the default when none are configured.
type Noop struct{}

var _ IAMMetrics = Noop{}

func (Noop) AuthSuccess()          {}
func (Noop) AuthFailure()          {}
func (Noop) TokenVerifySuccess()   {}
func (Noop) TokenVerifyFailure()   {}
func (Noop) TokenRefreshSuccess()  {}
func (Noop) TokenRefreshFailure()  {}
func (Noop) SessionRevokeSuccess() {}
func (Noop) SessionRevokeFailure() {}
func (Noop) PolicyDenied()         {}
