package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// manager is the default implementation of Manager.
type manager struct {
	store Store
	ttl   time.Duration
}

// NewManager creates a session manager using the given store.
//
// ttl defines refresh token lifetime.
//
// TODO:
//   - Per-client TTL
//   - Sliding expiration
//   - Rotation / reuse detection
func NewManager(
	store Store,
	ttl time.Duration,
) Manager {
	return &manager{
		store: store,
		ttl:   ttl,
	}
}

// Create establishes a new session (refresh token).
func (m *manager) Create(
	ctx context.Context,
	subjectID string,
	attrs map[string]string,
) (*Session, error) {

	id, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	now := time.Now()

	sess := &Session{
		ID:        id,
		SubjectID: subjectID,
		CreatedAt: now,
		LastUsed:  now,
		ExpiresAt: now.Add(m.ttl),
		Attrs:     attrs,
	}

	if err := m.store.Save(ctx, sess); err != nil {
		return nil, err
	}

	return sess, nil
}

// Validate checks whether a session exists and is active.
func (m *manager) Validate(
	ctx context.Context,
	sessionID string,
) (*Session, error) {

	sess, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return nil, errors.New("invalid or expired session")
	}

	return sess, nil
}

// Touch updates last-used timestamp.
func (m *manager) Touch(
	ctx context.Context,
	sessionID string,
) error {

	sess, err := m.store.Get(ctx, sessionID)
	if err != nil {
		return err
	}

	sess.LastUsed = time.Now()
	return m.store.Update(ctx, sess)
}

// Revoke invalidates a session permanently.
func (m *manager) Revoke(
	ctx context.Context,
	sessionID string,
) error {
	return m.store.Delete(ctx, sessionID)
}

// generateSessionID creates a cryptographically secure opaque token.
func generateSessionID() (string, error) {

	b := make([]byte, 32) // 256-bit
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
