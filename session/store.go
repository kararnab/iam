package session

import "context"

// Store defines the persistence contract for sessions.
//
// Store is deliberately separated from Manager so that:
//   - storage can be swapped (in-memory, Redis, SQL)
//   - testing can be isolated
//   - session logic does not leak storage concerns
type Store interface {

	// Save persists a newly created session.
	//
	// Expected behavior:
	//   - Fail if session ID already exists
	//   - Persist all session fields atomically
	Save(
		ctx context.Context,
		session *Session,
	) error

	// Get retrieves a session by ID.
	//
	// Expected behavior:
	//   - Return error if session does not exist
	//   - Return expired sessions (caller decides validity)
	Get(
		ctx context.Context,
		sessionID string,
	) (*Session, error)

	// Update updates mutable session fields.
	//
	// Typically used for:
	//   - last-used timestamp
	//   - attribute updates
	Update(
		ctx context.Context,
		session *Session,
	) error

	// Delete removes a session by ID (permanently).
	//
	// Used for:
	//   - logout
	//   - revocation
	//   - security events
	Delete(
		ctx context.Context,
		sessionID string,
	) error

	// DeleteBySubject removes all sessions for a subject.
	//
	// Used for "logout everywhere".
	DeleteBySubject(
		ctx context.Context,
		subjectID string,
	) error
}
