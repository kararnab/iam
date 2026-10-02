// Package memstore provides in-memory reference implementations of every
// store interface in the library. They are safe for concurrent use, lose all
// data on restart, and are intended for tests, demos and as a template for
// real stores.
package memstore

import (
	"context"
	"crypto/rand"
	"maps"
	"slices"
	"sync"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/provider"
)

type identityKey struct{ provider, providerID string }

// Users implements iam.SubjectLoader, iam.IdentityStore and
// password.CredentialStore.
type Users struct {
	mu         sync.RWMutex
	subjects   map[string]iam.Subject
	identities map[identityKey]string // -> subject ID
	creds      map[string]string      // login -> encoded hash
}

var (
	_ iam.UserStore            = (*Users)(nil)
	_ password.CredentialStore = (*Users)(nil)
)

// NewUsers returns an empty user store.
func NewUsers() *Users {
	return &Users{
		subjects:   make(map[string]iam.Subject),
		identities: make(map[identityKey]string),
		creds:      make(map[string]string),
	}
}

func clone(s iam.Subject) iam.Subject {
	s.Roles = slices.Clone(s.Roles)
	s.Attrs = maps.Clone(s.Attrs)
	return s
}

// PutSubject creates or replaces a subject. It is meant for seeding and for
// applications changing roles or disabling a subject.
func (u *Users) PutSubject(s iam.Subject) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.subjects[s.ID] = clone(s)
}

// LoadSubject implements iam.SubjectLoader.
func (u *Users) LoadSubject(_ context.Context, subjectID string) (*iam.Subject, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	s, ok := u.subjects[subjectID]
	if !ok {
		return nil, iam.ErrNotFound
	}
	c := clone(s)
	return &c, nil
}

// ResolveIdentity implements iam.IdentityStore.
func (u *Users) ResolveIdentity(_ context.Context, prov, providerID string) (string, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	id, ok := u.identities[identityKey{prov, providerID}]
	if !ok {
		return "", iam.ErrNotFound
	}
	return id, nil
}

// LinkIdentity implements iam.IdentityStore.
func (u *Users) LinkIdentity(_ context.Context, subjectID string, id provider.Identity) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.subjects[subjectID]; !ok {
		return iam.ErrNotFound
	}
	k := identityKey{id.Provider, id.ProviderID}
	if _, ok := u.identities[k]; ok {
		return iam.ErrConflict
	}
	u.identities[k] = subjectID
	return nil
}

// UnlinkIdentity implements iam.IdentityStore.
func (u *Users) UnlinkIdentity(_ context.Context, subjectID, prov, providerID string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	k := identityKey{prov, providerID}
	if u.identities[k] == subjectID {
		delete(u.identities, k)
	}
	return nil
}

// CreateSubject implements iam.IdentityStore. New subjects get a random ID
// and the roles from the grant.
func (u *Users) CreateSubject(_ context.Context, _ provider.Identity, grant iam.SignupGrant) (string, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	id := rand.Text()
	u.subjects[id] = iam.Subject{ID: id, Roles: slices.Clone(grant.Roles)}
	return id, nil
}

// Identities returns the identities linked to a subject, for display.
func (u *Users) Identities(subjectID string) []provider.Identity {
	u.mu.RLock()
	defer u.mu.RUnlock()
	var out []provider.Identity
	for k, sid := range u.identities {
		if sid == subjectID {
			out = append(out, provider.Identity{Provider: k.provider, ProviderID: k.providerID})
		}
	}
	return out
}

// GetCredential implements password.CredentialStore.
func (u *Users) GetCredential(_ context.Context, login string) (string, error) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	h, ok := u.creds[login]
	if !ok {
		return "", iam.ErrNotFound
	}
	return h, nil
}

// CreateCredential implements password.CredentialStore.
func (u *Users) CreateCredential(_ context.Context, login, encodedHash string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.creds[login]; ok {
		return iam.ErrConflict
	}
	u.creds[login] = encodedHash
	return nil
}

// UpdateCredential implements password.CredentialStore.
func (u *Users) UpdateCredential(_ context.Context, login, encodedHash string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, ok := u.creds[login]; !ok {
		return iam.ErrNotFound
	}
	u.creds[login] = encodedHash
	return nil
}

// DeleteCredential implements password.CredentialStore.
func (u *Users) DeleteCredential(_ context.Context, login string) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.creds, login)
	return nil
}
