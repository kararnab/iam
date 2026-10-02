package audit

import "context"

// EventType represents the category of an audit event.
//
// These events are security-relevant and should be treated as immutable.
type EventType string

const (
	EventAuthSuccess        EventType = "auth_success"
	EventAuthFailure        EventType = "auth_failure"
	EventTokenRefresh       EventType = "token_refresh"
	EventTokenVerifyFailure EventType = "token_verify_failure"
	EventSessionRevoked     EventType = "session_revoked"
	EventPolicyDenied       EventType = "policy_denied"
)

// Event represents a single audit log entry.
//
// Audit events are intentionally generic so they can be:
//   - written to logs
//   - pushed to SIEM systems
//   - stored in databases
//   - streamed to Kafka
type Event struct {
	Type      EventType
	SubjectID string            // internal subject identifier (if known)
	Provider  string            // auth provider involved (if applicable)
	Message   string            // human-readable description
	Attrs     map[string]string // extensible metadata (ip, device, reason, etc)
}

// Logger defines the contract for recording audit events.
//
// IAM emits audit events but does NOT decide where they go.
// Implementations may log to:
//   - stdout
//   - files
//   - databases
//   - message queues
type Logger interface {

	// Log records an audit event.
	//
	// TODO:
	//   - Async / buffered logging
	//   - Failure handling strategy
	//   - Correlation / trace IDs
	Log(
		ctx context.Context,
		event Event,
	) error
}
