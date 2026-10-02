package memstore

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/kararnab/iam/v2/session"
)

type hashEntry struct {
	sessionID string
	rotatedAt time.Time // zero for the current token
}

// Sessions implements session.Store.
type Sessions struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
	hashes   map[string][][sha256.Size]byte // session ID -> current and rotated hashes
	byHash   map[[sha256.Size]byte]hashEntry
	creates  int
}

var _ session.Store = (*Sessions)(nil)

// NewSessions returns an empty session store.
func NewSessions() *Sessions {
	return &Sessions{
		sessions: make(map[string]*session.Session),
		hashes:   make(map[string][][sha256.Size]byte),
		byHash:   make(map[[sha256.Size]byte]hashEntry),
	}
}

func key(h []byte) ([sha256.Size]byte, bool) {
	var k [sha256.Size]byte
	if len(h) != sha256.Size {
		return k, false
	}
	copy(k[:], h)
	return k, true
}

func copySession(s *session.Session) *session.Session {
	c := *s
	c.TokenHash = slices.Clone(s.TokenHash)
	c.Attrs = maps.Clone(s.Attrs)
	return &c
}

// Create implements session.Store.
func (m *Sessions) Create(_ context.Context, s *session.Session) error {
	k, ok := key(s.TokenHash)
	if !ok {
		return errors.New("memstore: invalid token hash")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[s.ID]; exists {
		return errors.New("memstore: session ID already exists")
	}
	if _, exists := m.byHash[k]; exists {
		return errors.New("memstore: token hash already exists")
	}
	m.sessions[s.ID] = copySession(s)
	m.hashes[s.ID] = [][sha256.Size]byte{k}
	m.byHash[k] = hashEntry{sessionID: s.ID}

	// Opportunistic cleanup so abandoned sessions do not accumulate.
	m.creates++
	if m.creates%256 == 0 {
		m.purgeLocked(time.Now())
	}
	return nil
}

// Get implements session.Store.
func (m *Sessions) Get(_ context.Context, id string) (*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, session.ErrNotFound
	}
	return copySession(s), nil
}

// GetByTokenHash implements session.Store.
func (m *Sessions) GetByTokenHash(_ context.Context, hash []byte) (*session.Session, session.TokenState, error) {
	k, ok := key(hash)
	if !ok {
		return nil, session.TokenState{}, session.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byHash[k]
	if !ok {
		return nil, session.TokenState{}, session.ErrNotFound
	}
	s, ok := m.sessions[e.sessionID]
	if !ok {
		return nil, session.TokenState{}, session.ErrNotFound
	}
	return copySession(s), session.TokenState{RotatedAt: e.rotatedAt}, nil
}

// Rotate implements session.Store.
func (m *Sessions) Rotate(_ context.Context, id string, oldHash, newHash []byte, at time.Time) error {
	oldK, ok1 := key(oldHash)
	newK, ok2 := key(newHash)
	if !ok1 || !ok2 {
		return errors.New("memstore: invalid token hash")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[id]
	if !ok {
		return session.ErrNotFound
	}
	if subtle.ConstantTimeCompare(s.TokenHash, oldHash) != 1 {
		return session.ErrConflict
	}
	if _, exists := m.byHash[newK]; exists {
		return errors.New("memstore: token hash already exists")
	}
	m.byHash[oldK] = hashEntry{sessionID: id, rotatedAt: at}
	m.byHash[newK] = hashEntry{sessionID: id}
	m.hashes[id] = append(m.hashes[id], newK)
	s.TokenHash = slices.Clone(newHash)
	s.LastUsedAt = at
	return nil
}

// Touch implements session.Store.
func (m *Sessions) Touch(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return session.ErrNotFound
	}
	s.LastUsedAt = at
	return nil
}

// Delete implements session.Store.
func (m *Sessions) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteLocked(id)
	return nil
}

func (m *Sessions) deleteLocked(id string) {
	if _, ok := m.sessions[id]; !ok {
		return
	}
	delete(m.sessions, id)
	for _, k := range m.hashes[id] {
		delete(m.byHash, k)
	}
	delete(m.hashes, id)
}

// ListBySubject implements session.Store.
func (m *Sessions) ListBySubject(_ context.Context, subjectID string) ([]*session.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*session.Session
	for _, s := range m.sessions {
		if s.SubjectID == subjectID {
			out = append(out, copySession(s))
		}
	}
	slices.SortFunc(out, func(a, b *session.Session) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

// DeleteBySubject implements session.Store.
func (m *Sessions) DeleteBySubject(_ context.Context, subjectID, exceptID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ids []string
	for id, s := range m.sessions {
		if s.SubjectID == subjectID && id != exceptID {
			ids = append(ids, id)
		}
	}
	for _, id := range ids {
		m.deleteLocked(id)
	}
	return len(ids), nil
}

// PurgeExpired removes sessions past their absolute expiry.
func (m *Sessions) PurgeExpired(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(now)
}

func (m *Sessions) purgeLocked(now time.Time) {
	for id, s := range m.sessions {
		if !now.Before(s.ExpiresAt) {
			m.deleteLocked(id)
		}
	}
}
