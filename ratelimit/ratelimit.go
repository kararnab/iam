// Package ratelimit throttles repeated failures, such as failed logins.
//
// The default behaviour is a growing back-off rather than a hard lockout:
// after Threshold failures within Window, the key is blocked for BaseDelay,
// and each further failure doubles the delay up to MaxDelay. A hard lockout
// lets anyone lock any user out, so it is left to LockoutHooks.
package ratelimit

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Result describes a key's state.
type Result struct {
	Allowed    bool          // false while the key is blocked
	RetryAfter time.Duration // how long until the block ends (0 if allowed)
	Failures   int           // failures counted in the current window
}

// Limiter tracks failures per key. Implementations must be safe for
// concurrent use. Keys are opaque strings chosen by the caller.
type Limiter interface {
	// Check reports whether key may make an attempt, without counting one.
	Check(ctx context.Context, key string) (Result, error)

	// Fail records a failure and returns the key's new state.
	Fail(ctx context.Context, key string) (Result, error)

	// Reset clears a key, typically after a successful attempt.
	Reset(ctx context.Context, key string) error
}

// LockoutHooks lets the application react to failures, for example to send
// a notification or apply a hard lockout in its own user store.
type LockoutHooks interface {
	// OnFailure is called after every recorded failure.
	OnFailure(ctx context.Context, key string, r Result)

	// OnBlocked is called when a failure causes key to become blocked.
	OnBlocked(ctx context.Context, key string, r Result)
}

// Config tunes the in-memory limiter. Zero values take the defaults shown.
type Config struct {
	Threshold int           // failures before blocking; default 5
	Window    time.Duration // failure counting window; default 15m
	BaseDelay time.Duration // first block; default 1s
	MaxDelay  time.Duration // cap on the block; default 15m
	MaxKeys   int           // memory bound; default 100k (oldest windows evicted first)

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Threshold == 0 {
		c.Threshold = 5
	}
	if c.Window == 0 {
		c.Window = 15 * time.Minute
	}
	if c.BaseDelay == 0 {
		c.BaseDelay = time.Second
	}
	if c.MaxDelay == 0 {
		c.MaxDelay = 15 * time.Minute
	}
	if c.MaxKeys == 0 {
		c.MaxKeys = 100_000
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

type entry struct {
	windowStart  time.Time
	failures     int
	blockedUntil time.Time
}

// Memory is an in-process Limiter. In a multi-instance deployment each
// instance counts separately; use a shared store (see the redisstore module).
type Memory struct {
	cfg  Config
	mu   sync.Mutex
	keys map[string]*entry
}

var _ Limiter = (*Memory)(nil)

// NewMemory returns an in-memory limiter.
func NewMemory(cfg Config) (*Memory, error) {
	cfg = cfg.withDefaults()
	if cfg.Threshold < 1 || cfg.Window <= 0 || cfg.BaseDelay <= 0 || cfg.MaxDelay < cfg.BaseDelay || cfg.MaxKeys < 1 {
		return nil, errors.New("ratelimit: invalid config")
	}
	return &Memory{cfg: cfg, keys: make(map[string]*entry)}, nil
}

func (m *Memory) state(e *entry, now time.Time) Result {
	if e == nil {
		return Result{Allowed: true}
	}
	if now.Before(e.blockedUntil) {
		return Result{Allowed: false, RetryAfter: e.blockedUntil.Sub(now), Failures: e.failures}
	}
	return Result{Allowed: true, Failures: e.failures}
}

// current returns key's entry, dropping it if its window and block are over.
func (m *Memory) current(key string, now time.Time) *entry {
	e := m.keys[key]
	if e != nil && !now.Before(e.windowStart.Add(m.cfg.Window)) && !now.Before(e.blockedUntil) {
		delete(m.keys, key)
		return nil
	}
	return e
}

// Check implements Limiter.
func (m *Memory) Check(_ context.Context, key string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Now()
	return m.state(m.current(key, now), now), nil
}

// Fail implements Limiter.
func (m *Memory) Fail(_ context.Context, key string) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Now()

	e := m.current(key, now)
	if e == nil {
		if len(m.keys) >= m.cfg.MaxKeys {
			m.evictLocked(now)
		}
		e = &entry{windowStart: now}
		m.keys[key] = e
	}
	e.failures++

	if over := e.failures - m.cfg.Threshold; over >= 0 {
		delay := m.cfg.BaseDelay
		for i := 0; i < over && delay < m.cfg.MaxDelay; i++ {
			delay *= 2
		}
		delay = min(delay, m.cfg.MaxDelay)
		e.blockedUntil = now.Add(delay)
		// Keep counting while blocked: the window extends to cover the block.
		if end := e.blockedUntil; end.After(e.windowStart.Add(m.cfg.Window)) {
			e.windowStart = end.Add(-m.cfg.Window)
		}
	}
	return m.state(e, now), nil
}

// Reset implements Limiter.
func (m *Memory) Reset(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.keys, key)
	return nil
}

// evictLocked drops expired entries, then the oldest windows if still full.
func (m *Memory) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, e := range m.keys {
		if !now.Before(e.windowStart.Add(m.cfg.Window)) && !now.Before(e.blockedUntil) {
			delete(m.keys, k)
			continue
		}
		if oldestKey == "" || e.windowStart.Before(oldest) {
			oldestKey, oldest = k, e.windowStart
		}
	}
	if len(m.keys) >= m.cfg.MaxKeys && oldestKey != "" {
		delete(m.keys, oldestKey)
	}
}
