// Package audit defines the security events IAM emits (logins, logouts,
// refreshes, refresh-token reuse, revocations, policy denials, sign-ups,
// invites, throttling) and the Logger interface that receives them.
//
// IAM decides what happened; the Logger decides where it goes. SlogLogger
// writes to log/slog; Multi and Func compose custom sinks. Events never
// contain passwords, tokens or session secrets.
package audit

import (
	"context"
	"time"
)

// EventType represents the category of an audit event.
//
// These events are security-relevant and should be treated as immutable.
type EventType string

const (
	EventLoginSuccess       EventType = "login_success"
	EventLoginFailure       EventType = "login_failure"
	EventLogout             EventType = "logout"
	EventRefreshSuccess     EventType = "refresh_success"
	EventRefreshFailure     EventType = "refresh_failure"
	EventRefreshReuse       EventType = "refresh_reuse_detected"
	EventSessionRotated     EventType = "session_rotated"
	EventSessionRevoked     EventType = "session_revoked"
	EventSessionsRevokedAll EventType = "sessions_revoked_all"
	EventTokenVerifyFailure EventType = "token_verify_failure"
	EventPolicyDenied       EventType = "policy_denied"
	EventIdentityLinked     EventType = "identity_linked"
	EventSignup             EventType = "signup"
	EventInviteCreated      EventType = "invite_created"
	EventInviteConsumed     EventType = "invite_consumed"
	EventRateLimited        EventType = "rate_limited"
	EventLockout            EventType = "lockout"
)

// Event represents a single audit log entry.
//
// Audit events are intentionally generic so they can be:
//   - written to logs
//   - pushed to SIEM systems
//   - stored in databases
//   - streamed to Kafka
//
// Events never contain secrets: no passwords, tokens or session secrets.
// SessionID is the public session identifier.
type Event struct {
	Time      time.Time
	Type      EventType
	SubjectID string            // canonical subject ID (if known)
	SessionID string            // public session ID (if known)
	Provider  string            // auth provider involved (if applicable)
	ClientIP  string            // client address as seen by the application
	Message   string            // human-readable description
	Attrs     map[string]string // extensible metadata (reason, count, ...)
}

// Logger defines the contract for recording audit events.
//
// IAM emits audit events but does NOT decide where they go. Log is called
// synchronously on the request path; slow sinks should buffer internally.
// Errors are reported to the caller but never fail the operation.
type Logger interface {
	Log(
		ctx context.Context,
		event Event,
	) error
}

// Func adapts a function to Logger.
type Func func(ctx context.Context, event Event) error

// Log implements Logger.
func (f Func) Log(ctx context.Context, event Event) error { return f(ctx, event) }

// Multi fans an event out to several loggers and returns the first error.
func Multi(loggers ...Logger) Logger {
	return Func(func(ctx context.Context, e Event) error {
		var first error
		for _, l := range loggers {
			if err := l.Log(ctx, e); err != nil && first == nil {
				first = err
			}
		}
		return first
	})
}
