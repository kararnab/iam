package session

import (
	"context"
	"errors"
	"maps"
	"time"
)

// Timeouts bound a session's lifetime.
type Timeouts struct {
	Idle     time.Duration // since last use
	Absolute time.Duration // since creation
}

// Config configures a Manager. Zero values take the defaults shown.
type Config struct {
	Cookie Timeouts // default: idle 30m, absolute 7 days
	Bearer Timeouts // default: idle 14 days, absolute 30 days

	// ReuseGrace is how long after a rotation the previous refresh token
	// fails with ErrRaced instead of revoking the session. Default 0: any
	// reuse revokes.
	ReuseGrace time.Duration

	// TouchInterval limits how often LastUsedAt is written in cookie mode.
	// Default 1 minute.
	TouchInterval time.Duration

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

func (c Config) withDefaults() Config {
	if c.Cookie.Idle == 0 {
		c.Cookie.Idle = 30 * time.Minute
	}
	if c.Cookie.Absolute == 0 {
		c.Cookie.Absolute = 7 * 24 * time.Hour
	}
	if c.Bearer.Idle == 0 {
		c.Bearer.Idle = 14 * 24 * time.Hour
	}
	if c.Bearer.Absolute == 0 {
		c.Bearer.Absolute = 30 * 24 * time.Hour
	}
	if c.TouchInterval == 0 {
		c.TouchInterval = time.Minute
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

func (c Config) timeouts(m Mode) Timeouts {
	if m == ModeBearer {
		return c.Bearer
	}
	return c.Cookie
}

// Manager implements session lifecycle on top of a Store.
type Manager struct {
	store Store
	cfg   Config
}

// NewManager returns a Manager.
func NewManager(store Store, cfg Config) (*Manager, error) {
	if store == nil {
		return nil, errors.New("session: store is required")
	}
	cfg = cfg.withDefaults()
	if cfg.ReuseGrace < 0 || cfg.ReuseGrace > time.Minute {
		return nil, errors.New("session: ReuseGrace must be between 0 and 1 minute")
	}
	return &Manager{store: store, cfg: cfg}, nil
}

// Create starts a session and returns it with its secret (the cookie value
// or refresh token). The secret is never stored.
func (m *Manager) Create(ctx context.Context, subjectID string, mode Mode, attrs map[string]string) (*Session, string, error) {
	if !mode.Valid() {
		return nil, "", errors.New("session: invalid mode")
	}
	now := m.cfg.Now()
	secret, hash := NewSecret()
	s := &Session{
		ID:         newID(),
		SubjectID:  subjectID,
		Mode:       mode,
		TokenHash:  hash,
		CreatedAt:  now,
		LastUsedAt: now,
		ExpiresAt:  now.Add(m.cfg.timeouts(mode).Absolute),
		Attrs:      maps.Clone(attrs),
	}
	if err := m.store.Create(ctx, s); err != nil {
		return nil, "", err
	}
	return s, secret, nil
}

// expired reports whether s is past its absolute or idle expiry.
func (m *Manager) expired(s *Session, now time.Time) bool {
	return !now.Before(s.ExpiresAt) || !now.Before(s.LastUsedAt.Add(m.cfg.timeouts(s.Mode).Idle))
}

// lookup finds the session for a secret and enforces mode and expiry.
// Expired sessions are deleted.
func (m *Manager) lookup(ctx context.Context, secret string, mode Mode) (*Session, TokenState, []byte, error) {
	hash, err := HashSecret(secret)
	if err != nil {
		return nil, TokenState{}, nil, ErrInvalid
	}
	s, state, err := m.store.GetByTokenHash(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, TokenState{}, nil, ErrInvalid
	}
	if err != nil {
		return nil, TokenState{}, nil, err
	}
	if s.Mode != mode {
		return nil, TokenState{}, nil, ErrInvalid
	}
	if m.expired(s, m.cfg.Now()) {
		_ = m.store.Delete(ctx, s.ID)
		return nil, TokenState{}, nil, ErrInvalid
	}
	return s, state, hash, nil
}

// Validate checks a cookie-mode session secret and records activity.
// A secret that was rotated away (see Rotate) is invalid.
func (m *Manager) Validate(ctx context.Context, secret string) (*Session, error) {
	s, state, _, err := m.lookup(ctx, secret, ModeCookie)
	if err != nil {
		return nil, err
	}
	if !state.RotatedAt.IsZero() {
		return nil, ErrInvalid
	}
	now := m.cfg.Now()
	if now.Sub(s.LastUsedAt) >= m.cfg.TouchInterval {
		if err := m.store.Touch(ctx, s.ID, now); err == nil {
			s.LastUsedAt = now
		}
	}
	return s, nil
}

// Rotate replaces a cookie-mode session secret (for example after a
// privilege change) and returns the new secret. The old secret stops working.
func (m *Manager) Rotate(ctx context.Context, secret string) (*Session, string, error) {
	s, state, hash, err := m.lookup(ctx, secret, ModeCookie)
	if err != nil {
		return nil, "", err
	}
	if !state.RotatedAt.IsZero() {
		return nil, "", ErrInvalid
	}
	return m.rotate(ctx, s, hash)
}

func (m *Manager) rotate(ctx context.Context, s *Session, oldHash []byte) (*Session, string, error) {
	now := m.cfg.Now()
	secret, newHash := NewSecret()
	if err := m.store.Rotate(ctx, s.ID, oldHash, newHash, now); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, "", ErrInvalid // revoked concurrently
		}
		return nil, "", err
	}
	s.TokenHash = newHash
	s.LastUsedAt = now
	return s, secret, nil
}

// Inspect checks a bearer-mode refresh token without rotating or touching
// it, and returns its session. It returns ErrInvalid for an unknown,
// expired or already rotated token; use Refresh to rotate (Refresh also
// detects reuse of rotated tokens). Store failures are returned as is.
//
// Inspect lets a caller check the session's subject before rotating, so
// that a failure there does not discard the client's refresh token.
func (m *Manager) Inspect(ctx context.Context, refreshToken string) (*Session, error) {
	s, state, _, err := m.lookup(ctx, refreshToken, ModeBearer)
	if err != nil {
		return nil, err
	}
	if !state.RotatedAt.IsZero() {
		return nil, ErrInvalid
	}
	return s, nil
}

// Refresh rotates a bearer-mode refresh token and returns the session and
// the new refresh token.
//
// Reuse of an already-rotated token revokes the session and returns
// ErrReused (or ErrRaced within Config.ReuseGrace). The returned session is
// non-nil for ErrReused and ErrRaced, so callers can audit it.
func (m *Manager) Refresh(ctx context.Context, refreshToken string) (*Session, string, error) {
	s, state, hash, err := m.lookup(ctx, refreshToken, ModeBearer)
	if err != nil {
		return nil, "", err
	}
	if !state.RotatedAt.IsZero() {
		return s, "", m.reused(ctx, s, state.RotatedAt)
	}

	rotated, secret, err := m.rotate(ctx, s, hash)
	if errors.Is(err, ErrConflict) {
		// Another request rotated this same token first.
		return s, "", m.reused(ctx, s, m.cfg.Now())
	}
	if err != nil {
		return nil, "", err
	}
	return rotated, secret, nil
}

func (m *Manager) reused(ctx context.Context, s *Session, rotatedAt time.Time) error {
	if m.cfg.ReuseGrace > 0 && m.cfg.Now().Sub(rotatedAt) <= m.cfg.ReuseGrace {
		return ErrRaced
	}
	if err := m.store.Delete(ctx, s.ID); err != nil {
		return err
	}
	return ErrReused
}

// Get returns an active session by public ID, or ErrInvalid.
func (m *Manager) Get(ctx context.Context, id string) (*Session, error) {
	s, err := m.store.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	if m.expired(s, m.cfg.Now()) {
		return nil, ErrInvalid
	}
	return s, nil
}

// Revoke ends the session that owns secret (a cookie secret or refresh
// token, current or rotated). Unknown secrets are not an error, so logout is
// idempotent. It returns the revoked session, or nil.
func (m *Manager) Revoke(ctx context.Context, secret string) (*Session, error) {
	hash, err := HashSecret(secret)
	if err != nil {
		// A malformed token cannot own a session, so there is nothing to end.
		return nil, nil //nolint:nilerr // logout is idempotent by design
	}
	s, _, err := m.store.GetByTokenHash(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, m.store.Delete(ctx, s.ID)
}

// RevokeByID ends one of subjectID's sessions. Sessions of other subjects
// are treated as not found, so callers cannot probe for them.
func (m *Manager) RevokeByID(ctx context.Context, subjectID, sessionID string) error {
	s, err := m.store.Get(ctx, sessionID)
	if errors.Is(err, ErrNotFound) || (err == nil && s.SubjectID != subjectID) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return m.store.Delete(ctx, sessionID)
}

// RevokeAll ends all of a subject's sessions except exceptID ("log out
// everywhere else"); pass "" to end all of them.
func (m *Manager) RevokeAll(ctx context.Context, subjectID, exceptID string) (int, error) {
	return m.store.DeleteBySubject(ctx, subjectID, exceptID)
}

// List returns a subject's active sessions.
func (m *Manager) List(ctx context.Context, subjectID string) ([]*Session, error) {
	all, err := m.store.ListBySubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	now := m.cfg.Now()
	out := all[:0]
	for _, s := range all {
		if !m.expired(s, now) {
			out = append(out, s)
		}
	}
	return out, nil
}
