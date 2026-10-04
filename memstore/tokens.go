package memstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/kararnab/iam/v2/onetime"
)

// Tokens implements onetime.Store.
type Tokens struct {
	mu     sync.Mutex
	byHash map[[sha256.Size]byte]*onetime.Token
}

var _ onetime.Store = (*Tokens)(nil)

// NewTokens returns an empty one-time token store.
func NewTokens() *Tokens {
	return &Tokens{byHash: make(map[[sha256.Size]byte]*onetime.Token)}
}

func copyToken(t *onetime.Token) *onetime.Token {
	c := *t
	c.TokenHash = slices.Clone(t.TokenHash)
	return &c
}

// Create implements onetime.Store.
func (m *Tokens) Create(_ context.Context, t *onetime.Token) error {
	k, ok := key(t.TokenHash)
	if !ok {
		return errors.New("memstore: invalid token hash")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byHash[k]; exists {
		return errors.New("memstore: token hash already exists")
	}
	for _, other := range m.byHash {
		if other.ID == t.ID {
			return errors.New("memstore: token ID already exists")
		}
	}
	m.byHash[k] = copyToken(t)
	return nil
}

// GetByTokenHash implements onetime.Store.
func (m *Tokens) GetByTokenHash(_ context.Context, hash []byte) (*onetime.Token, error) {
	k, ok := key(hash)
	if !ok {
		return nil, onetime.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byHash[k]
	if !ok {
		return nil, onetime.ErrNotFound
	}
	return copyToken(t), nil
}

// Consume implements onetime.Store.
func (m *Tokens) Consume(_ context.Context, hash []byte, purpose onetime.Purpose, at time.Time) (*onetime.Token, error) {
	k, ok := key(hash)
	if !ok {
		return nil, onetime.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.byHash[k]
	if !ok || t.Purpose != purpose || !t.Usable(at) {
		return nil, onetime.ErrInvalid
	}
	t.UsedAt = at
	return copyToken(t), nil
}

// DeleteBySubject implements onetime.Store.
func (m *Tokens) DeleteBySubject(_ context.Context, subjectID string, purpose onetime.Purpose) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, t := range m.byHash {
		if t.SubjectID == subjectID && t.Purpose == purpose {
			delete(m.byHash, k)
		}
	}
	return nil
}
