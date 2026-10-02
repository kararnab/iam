package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

// memoryStore is an in-memory, Redis-like implementation of Store.
//
// Semantics:
//   - sessionID is the key
//   - expiry is enforced by the store
//   - expired sessions behave as "not found"
//   - expired sessions are deleted on access
type memoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewMemoryStore creates an in-memory session store.
//
// TODO:
//   - Background cleanup goroutine (optional)
//   - Metrics hooks
func NewMemoryStore() Store {
	return &memoryStore{
		sessions: make(map[string]*Session),
	}
}

func (s *memoryStore) Save(
	ctx context.Context,
	session *Session,
) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.ID]; exists {
		return errors.New("session already exists")
	}

	s.sessions[session.ID] = session
	return nil
}

func (s *memoryStore) Get(
	ctx context.Context,
	sessionID string,
) (*Session, error) {

	// Write lock: expired sessions are deleted on access.
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return nil, errors.New("session not found")
	}

	// Enforce TTL (Redis-like behavior)
	if time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, sessionID)
		return nil, errors.New("session expired")
	}

	return sess, nil
}

func (s *memoryStore) Update(
	ctx context.Context,
	session *Session,
) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.sessions[session.ID]; !ok {
		return errors.New("session not found")
	}

	s.sessions[session.ID] = session
	return nil
}

func (s *memoryStore) Delete(
	ctx context.Context,
	sessionID string,
) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, sessionID)
	return nil
}

func (s *memoryStore) DeleteBySubject(
	ctx context.Context,
	subjectID string,
) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	for id, sess := range s.sessions {
		if sess.SubjectID == subjectID {
			delete(s.sessions, id)
		}
	}

	return nil
}
