package memstore

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/kararnab/iam/v2/passkey"
)

// Passkeys implements passkey.Store.
type Passkeys struct {
	mu    sync.Mutex
	byID  map[string]*passkey.Credential
	order []string // creation order
}

var _ passkey.Store = (*Passkeys)(nil)

// NewPasskeys returns an empty credential store.
func NewPasskeys() *Passkeys { return &Passkeys{byID: make(map[string]*passkey.Credential)} }

func copyCredential(c *passkey.Credential) *passkey.Credential {
	d := *c
	d.ID = slices.Clone(c.ID)
	d.PublicKey = slices.Clone(c.PublicKey)
	d.AAGUID = slices.Clone(c.AAGUID)
	d.Transports = slices.Clone(c.Transports)
	return &d
}

// Create implements passkey.Store.
func (m *Passkeys) Create(_ context.Context, c *passkey.Credential) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(c.ID)
	if _, ok := m.byID[k]; ok {
		return passkey.ErrConflict
	}
	m.byID[k] = copyCredential(c)
	m.order = append(m.order, k)
	return nil
}

// Get implements passkey.Store.
func (m *Passkeys) Get(_ context.Context, id []byte) (*passkey.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[string(id)]
	if !ok {
		return nil, passkey.ErrNotFound
	}
	return copyCredential(c), nil
}

// ListBySubject implements passkey.Store.
func (m *Passkeys) ListBySubject(_ context.Context, subjectID string) ([]*passkey.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*passkey.Credential
	for _, k := range m.order {
		if c := m.byID[k]; c != nil && c.SubjectID == subjectID {
			out = append(out, copyCredential(c))
		}
	}
	return out, nil
}

// Touch implements passkey.Store.
func (m *Passkeys) Touch(_ context.Context, id []byte, signCount uint32, backupState bool, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.byID[string(id)]
	if !ok {
		return passkey.ErrNotFound
	}
	c.SignCount, c.BackupState, c.LastUsedAt = signCount, backupState, at
	return nil
}

// Delete implements passkey.Store.
func (m *Passkeys) Delete(_ context.Context, subjectID string, id []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := string(id)
	if c, ok := m.byID[k]; ok && c.SubjectID == subjectID {
		delete(m.byID, k)
		m.order = slices.DeleteFunc(m.order, func(o string) bool { return o == k })
	}
	return nil
}
