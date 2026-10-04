package memstore

import (
	"bytes"
	"context"
	"slices"
	"sync"

	"github.com/kararnab/iam/v2/mfa"
)

// MFA implements mfa.Store.
type MFA struct {
	mu   sync.Mutex
	totp map[string]*mfa.TOTP
}

var _ mfa.Store = (*MFA)(nil)

// NewMFA returns an empty MFA store.
func NewMFA() *MFA { return &MFA{totp: make(map[string]*mfa.TOTP)} }

func copyTOTP(t *mfa.TOTP) *mfa.TOTP {
	c := *t
	c.Secret = slices.Clone(t.Secret)
	c.RecoveryCodes = make([][]byte, len(t.RecoveryCodes))
	for i, h := range t.RecoveryCodes {
		c.RecoveryCodes[i] = slices.Clone(h)
	}
	return &c
}

// GetTOTP implements mfa.Store.
func (m *MFA) GetTOTP(_ context.Context, subjectID string) (*mfa.TOTP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.totp[subjectID]
	if !ok {
		return nil, mfa.ErrNotFound
	}
	return copyTOTP(t), nil
}

// PutTOTP implements mfa.Store.
func (m *MFA) PutTOTP(_ context.Context, t *mfa.TOTP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totp[t.SubjectID] = copyTOTP(t)
	return nil
}

// DeleteTOTP implements mfa.Store.
func (m *MFA) DeleteTOTP(_ context.Context, subjectID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.totp, subjectID)
	return nil
}

// AdvanceTOTP implements mfa.Store.
func (m *MFA) AdvanceTOTP(_ context.Context, subjectID string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.totp[subjectID]
	if !ok || step <= t.LastStep {
		return false, nil
	}
	t.LastStep = step
	return true, nil
}

// UseRecoveryCode implements mfa.Store.
func (m *MFA) UseRecoveryCode(_ context.Context, subjectID string, hash []byte) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.totp[subjectID]
	if !ok {
		return false, nil
	}
	i := slices.IndexFunc(t.RecoveryCodes, func(h []byte) bool { return bytes.Equal(h, hash) })
	if i < 0 {
		return false, nil
	}
	t.RecoveryCodes = slices.Delete(t.RecoveryCodes, i, i+1)
	return true, nil
}
