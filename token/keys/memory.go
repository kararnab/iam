package keys

import (
	"errors"
	"sync"
)

// MemoryProvider is an in-memory rotating key provider.
//
// NOT for distributed systems (yet).
// Perfect for monolith / MVP.
type MemoryProvider struct {
	mu     sync.RWMutex
	active Key
	old    []Key
}

// NewMemoryProvider creates a key provider with an initial active key.
func NewMemoryProvider(initial Key) *MemoryProvider {
	return &MemoryProvider{
		active: initial,
		old:    nil,
	}
}

// ActiveKey returns the current active key.
func (p *MemoryProvider) ActiveKey() Key {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.active
}

// VerificationKeys returns all keys valid for verification.
//
// Order matters:
//   - active key first (fast path)
//   - then older keys
func (p *MemoryProvider) VerificationKeys() []Key {
	p.mu.RLock()
	defer p.mu.RUnlock()

	keys := make([]Key, 0, 1+len(p.old))
	keys = append(keys, p.active)
	keys = append(keys, p.old...)
	return keys
}

// Rotate promotes a new key to active.
//
// Old active key is retained for verification. The new key ID must be
// non-empty and must not match any key already held.
func (p *MemoryProvider) Rotate(newKey Key) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if newKey.ID == "" {
		return errors.New("keys: key ID is required")
	}
	if newKey.ID == p.active.ID {
		return errors.New("keys: duplicate key ID")
	}
	for _, k := range p.old {
		if k.ID == newKey.ID {
			return errors.New("keys: duplicate key ID")
		}
	}

	p.old = append([]Key{p.active}, p.old...)
	p.active = newKey
	return nil
}

// Prune removes old keys beyond retention count.
//
// Call this AFTER rotation window expires.
func (p *MemoryProvider) Prune(maxOld int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if maxOld >= 0 && len(p.old) > maxOld {
		p.old = p.old[:maxOld]
	}
}
