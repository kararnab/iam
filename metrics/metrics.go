// Package metrics defines the counters IAM emits.
//
// Recorder takes a fixed, low-cardinality set of events, so adding an event
// in a later version does not break implementations. No subject IDs,
// tokens or other high-cardinality values are ever passed.
package metrics

// Event names a counter.
type Event string

const (
	LoginSuccess       Event = "login_success"
	LoginFailure       Event = "login_failure"
	Logout             Event = "logout"
	RefreshSuccess     Event = "refresh_success"
	RefreshFailure     Event = "refresh_failure"
	RefreshReuse       Event = "refresh_reuse"
	TokenVerifySuccess Event = "token_verify_success" //nolint:gosec // G101: a metric name, not a credential
	TokenVerifyFailure Event = "token_verify_failure"
	SessionRevoked     Event = "session_revoked"
	PolicyDenied       Event = "policy_denied"
	Signup             Event = "signup"
	SignupFailure      Event = "signup_failure"
	RateLimited        Event = "rate_limited"
)

// Events lists every Event, for backends that pre-register counters.
var Events = []Event{
	LoginSuccess, LoginFailure, Logout,
	RefreshSuccess, RefreshFailure, RefreshReuse,
	TokenVerifySuccess, TokenVerifyFailure,
	SessionRevoked, PolicyDenied,
	Signup, SignupFailure, RateLimited,
}

// Recorder counts events. Implementations must be safe for concurrent use
// and must not block.
type Recorder interface {
	Inc(e Event)
}

// Noop discards all metrics. It is the default when none are configured.
type Noop struct{}

// Inc implements Recorder.
func (Noop) Inc(Event) {}
