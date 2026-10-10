// Package session manages server-side sessions for both session modes:
//
//   - ModeCookie: the client holds an opaque session secret in a cookie.
//   - ModeBearer: the client holds an opaque refresh token and short-lived
//     access tokens. The session is the refresh-token family.
//
// Secrets are 256-bit random values. Stores only ever see their SHA-256 hash,
// and look sessions up by that hash, so a leaked database does not contain
// usable credentials and lookups leak nothing useful through timing.
//
// Every refresh rotates the refresh token. Presenting a token that was
// already rotated revokes the whole session (reuse detection), unless it
// happens within Config.ReuseGrace (a client that sent two refreshes at once).
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"
)

// Mode selects how a client holds its session.
type Mode string

const (
	ModeCookie Mode = "cookie"
	ModeBearer Mode = "bearer"
)

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return m == ModeCookie || m == ModeBearer }

var (
	// ErrInvalid is returned for unknown, expired, revoked or malformed
	// session secrets, and for a secret used in the wrong mode.
	ErrInvalid = errors.New("session: invalid or expired")

	// ErrReused is returned when an already-rotated refresh token is
	// presented. The session has been revoked.
	ErrReused = errors.New("session: refresh token reuse detected; session revoked")

	// ErrRaced is returned when a just-rotated refresh token is presented
	// again within Config.ReuseGrace. The session is kept.
	ErrRaced = errors.New("session: refresh token was just rotated")

	// ErrNotFound is returned by stores for missing sessions.
	ErrNotFound = errors.New("session: not found")

	// ErrConflict is returned by Store.Rotate when the session's current
	// token hash is no longer the expected one (a concurrent rotation won).
	ErrConflict = errors.New("session: concurrent rotation")
)

// Session is the server-side record. It never contains a secret.
type Session struct {
	ID        string // public, random identifier; safe to show and log ("sid")
	SubjectID string
	Mode      Mode
	TokenHash []byte // SHA-256 of the current secret

	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time // absolute expiry; idle expiry is LastUsedAt + idle timeout

	Attrs map[string]string // ip, user_agent, provider, ...
}

// TokenState describes the token a lookup matched.
type TokenState struct {
	// RotatedAt is zero if the hash is the session's current token, and
	// otherwise the time it was rotated away.
	RotatedAt time.Time
}

// Store persists sessions. Implementations must be safe for concurrent use,
// and Rotate must be atomic.
type Store interface {
	// Create persists a new session. The ID and TokenHash are unique.
	Create(ctx context.Context, s *Session) error

	// Get returns a session by public ID, or ErrNotFound.
	Get(ctx context.Context, id string) (*Session, error)

	// GetByTokenHash returns the session whose current or previously
	// rotated token has this hash, or ErrNotFound.
	GetByTokenHash(ctx context.Context, hash []byte) (*Session, TokenState, error)

	// Rotate replaces the session's current token hash with newHash, but
	// only if it is still oldHash (otherwise ErrConflict). oldHash is kept
	// as a rotated hash, recorded at time at, for reuse detection. It also
	// sets LastUsedAt to at.
	Rotate(ctx context.Context, id string, oldHash, newHash []byte, at time.Time) error

	// Touch sets LastUsedAt.
	Touch(ctx context.Context, id string, at time.Time) error

	// Delete removes a session and its rotated hashes. Missing is not an error.
	Delete(ctx context.Context, id string) error

	// ListBySubject returns a subject's sessions, including expired ones
	// that have not been purged yet.
	ListBySubject(ctx context.Context, subjectID string) ([]*Session, error)

	// DeleteBySubject removes all of a subject's sessions except exceptID
	// (which may be empty) and returns how many were removed.
	DeleteBySubject(ctx context.Context, subjectID, exceptID string) (int, error)
}

// Purger is implemented by stores that keep expired sessions until they
// are removed (SQL databases). The manager already rejects expired
// sessions; purging only bounds storage. Call it periodically, for example
// hourly, from one or every instance (it is idempotent).
//
// Stores whose records expire on their own (Redis key TTLs, memstore,
// which purges as it goes) need not implement it.
type Purger interface {
	// PurgeExpired deletes sessions whose absolute expiry is at or before
	// now, with their rotated token hashes, and returns how many sessions
	// it deleted.
	PurgeExpired(ctx context.Context, now time.Time) (int, error)
}

// secretLen is the decoded length of a session secret.
const secretLen = 32

// encodedSecretLen is the length of a base64url-encoded secret.
var encodedSecretLen = base64.RawURLEncoding.EncodedLen(secretLen)

// NewSecret returns a new random secret and its hash.
func NewSecret() (secret string, hash []byte) {
	b := make([]byte, secretLen)
	_, _ = rand.Read(b) // never fails (crypto/rand, Go 1.24+)
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(b), sum[:]
}

// HashSecret validates the encoding of a client-supplied secret and returns
// its hash. Anything other than exactly 43 base64url characters is rejected
// before decoding.
func HashSecret(secret string) ([]byte, error) {
	if len(secret) != encodedSecretLen {
		return nil, ErrInvalid
	}
	for i := 0; i < len(secret); i++ {
		c := secret[i]
		if !isBase64URL(c) {
			return nil, ErrInvalid
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(b) != secretLen {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// isBase64URL reports whether c is in the base64url alphabet (RFC 4648 §5).
func isBase64URL(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

// newID returns a public session ID (130 random bits, base32).
func newID() string { return rand.Text() }
