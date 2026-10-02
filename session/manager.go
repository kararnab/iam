package session

import (
	"context"
	"time"
)

// Session represents a long-lived authenticated session.
// A session is typically backed by a refresh token.
//
// Sessions are stateful by design.
type Session struct {
	ID        string // opaque session identifier (refresh token)
	SubjectID string // internal subject ID
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time
	Attrs     map[string]string // device, client_id, ip, etc
}

// Manager defines session lifecycle operations.
//
// The Manager owns refresh-token semantics and is responsible for:
//   - creating sessions
//   - validating sessions
//   - revoking sessions
//   - rotating refresh tokens (eventually)
type Manager interface {

	// Create establishes a new session for a subject.
	//
	// Expected behavior:
	//   - Generate a secure, opaque session ID
	//   - Persist session state
	//   - Enforce session limits per subject/client
	//
	// TODO:
	//   - Device binding
	//   - Concurrent session limits
	//   - Risk-based expiry
	Create(
		ctx context.Context,
		subjectID string,
		attrs map[string]string,
	) (*Session, error)

	// Validate checks whether a session is valid and active.
	//
	// Expected behavior:
	//   - Lookup session
	//   - Check expiry
	//   - Check revocation status
	//
	// TODO:
	//   - Refresh token rotation detection
	//   - Sliding expiration
	Validate(
		ctx context.Context,
		sessionID string,
	) (*Session, error)

	// Touch updates last-used timestamp for a session.
	//
	// This is optional but useful for:
	//   - inactivity-based expiry
	//   - audit trails
	Touch(
		ctx context.Context,
		sessionID string,
	) error

	// Revoke invalidates a session permanently.
	//
	// TODO:
	//   - Revoke all sessions for a subject
	//   - Revoke by device / client
	Revoke(
		ctx context.Context,
		sessionID string,
	) error
}
