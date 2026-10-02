package memstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/kararnab/iam/v2/invite"
)

// Invites implements invite.Store.
type Invites struct {
	mu     sync.Mutex
	byHash map[[sha256.Size]byte]*invite.Invite
}

var _ invite.Store = (*Invites)(nil)

// NewInvites returns an empty invite store.
func NewInvites() *Invites {
	return &Invites{byHash: make(map[[sha256.Size]byte]*invite.Invite)}
}

func copyInvite(i *invite.Invite) *invite.Invite {
	c := *i
	c.TokenHash = slices.Clone(i.TokenHash)
	c.Roles = slices.Clone(i.Roles)
	return &c
}

// Create implements invite.Store.
func (m *Invites) Create(_ context.Context, inv *invite.Invite) error {
	k, ok := key(inv.TokenHash)
	if !ok {
		return errors.New("memstore: invalid token hash")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byHash[k]; exists {
		return errors.New("memstore: token hash already exists")
	}
	m.byHash[k] = copyInvite(inv)
	return nil
}

// GetByTokenHash implements invite.Store.
func (m *Invites) GetByTokenHash(_ context.Context, hash []byte) (*invite.Invite, error) {
	k, ok := key(hash)
	if !ok {
		return nil, invite.ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.byHash[k]
	if !ok {
		return nil, invite.ErrNotFound
	}
	return copyInvite(inv), nil
}

// Consume implements invite.Store.
func (m *Invites) Consume(_ context.Context, hash []byte, usedBy string, at time.Time) (*invite.Invite, error) {
	k, ok := key(hash)
	if !ok {
		return nil, invite.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.byHash[k]
	if !ok || !inv.Usable(at) {
		return nil, invite.ErrInvalid
	}
	inv.UsedAt, inv.UsedBy = at, usedBy
	return copyInvite(inv), nil
}

// Delete implements invite.Store.
func (m *Invites) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, inv := range m.byHash {
		if inv.ID == id {
			delete(m.byHash, k)
		}
	}
	return nil
}
