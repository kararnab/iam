package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2/ratelimit"
)

// Limiter implements ratelimit.Limiter on PostgreSQL (table
// iam_rate_limits), so throttling is shared by every instance, for
// applications that have PostgreSQL but no Redis. It has the same
// semantics as ratelimit.Memory and redisstore.Limiter: after Threshold
// failures within Window the key is blocked for BaseDelay, doubling per
// further failure up to MaxDelay.
//
//	perLogin, _ := pgstore.NewLimiter(pool, ratelimit.Config{Threshold: 5})
//	perIP, _ := pgstore.NewLimiter(pool, ratelimit.Config{Threshold: 100})
//	cfg.RateLimit = iam.RateLimitConfig{PerLogin: perLogin, PerIP: perIP}
//
// Both limiters can share the table: iam's per-login and per-IP keys never
// collide. Two limiters with different Config must not share keys.
//
// Check is one query; Fail is a short transaction that locks the key's row,
// so concurrent failures are all counted. Dead rows (window and block both
// over) are ignored, and removed by PurgeExpired; call it periodically.
type Limiter struct {
	db  DB
	cfg ratelimit.Config
}

var _ ratelimit.Limiter = (*Limiter)(nil)

// NewLimiter returns a PostgreSQL limiter. Zero config values take the
// ratelimit defaults; MaxKeys is ignored (PurgeExpired bounds the table).
func NewLimiter(db DB, cfg ratelimit.Config) (*Limiter, error) {
	if cfg.Threshold == 0 {
		cfg.Threshold = 5
	}
	if cfg.Window == 0 {
		cfg.Window = 15 * time.Minute
	}
	if cfg.BaseDelay == 0 {
		cfg.BaseDelay = time.Second
	}
	if cfg.MaxDelay == 0 {
		cfg.MaxDelay = 15 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Threshold < 1 || cfg.Window <= 0 || cfg.BaseDelay <= 0 || cfg.MaxDelay < cfg.BaseDelay {
		return nil, errors.New("pgstore: invalid limiter config")
	}
	return &Limiter{db: db, cfg: cfg}, nil
}

// limitState is one key's row.
type limitState struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
}

// now is the configured clock at PostgreSQL's precision, so that times read
// back compare exactly with times computed.
func (l *Limiter) now() time.Time { return l.cfg.Now().Truncate(time.Microsecond) }

// dead reports whether the window and the block are both over.
func (l *Limiter) dead(st limitState, now time.Time) bool {
	return !now.Before(st.windowStart.Add(l.cfg.Window)) && !now.Before(st.blockedUntil)
}

func (l *Limiter) result(st limitState, now time.Time) ratelimit.Result {
	if now.Before(st.blockedUntil) {
		return ratelimit.Result{Allowed: false, RetryAfter: st.blockedUntil.Sub(now), Failures: st.failures}
	}
	return ratelimit.Result{Allowed: true, Failures: st.failures}
}

// Check implements ratelimit.Limiter.
func (l *Limiter) Check(ctx context.Context, key string) (ratelimit.Result, error) {
	now := l.now()
	var st limitState
	err := l.db.QueryRow(ctx, `SELECT failures, window_start, blocked_until FROM iam_rate_limits WHERE key = $1`, key).
		Scan(&st.failures, &st.windowStart, &st.blockedUntil)
	if isNoRows(err) || (err == nil && l.dead(st, now)) {
		return ratelimit.Result{Allowed: true}, nil
	}
	if err != nil {
		return ratelimit.Result{}, err
	}
	return l.result(st, now), nil
}

// Fail implements ratelimit.Limiter.
func (l *Limiter) Fail(ctx context.Context, key string) (ratelimit.Result, error) {
	now := l.now()
	tx, err := l.db.Begin(ctx)
	if err != nil {
		return ratelimit.Result{}, err
	}
	// Rollback after Commit is a no-op that returns pgx.ErrTxClosed.
	defer func() { _ = tx.Rollback(ctx) }()

	// Create the row if needed, then lock it: concurrent failures of one
	// key queue here, so each sees the previous one's count.
	if _, err := tx.Exec(ctx, `
		INSERT INTO iam_rate_limits (key, failures, window_start, blocked_until, expires_at)
		VALUES ($1, 0, $2, $2, $2) ON CONFLICT (key) DO NOTHING`, key, now); err != nil {
		return ratelimit.Result{}, err
	}
	var st limitState
	if err := tx.QueryRow(ctx, `SELECT failures, window_start, blocked_until FROM iam_rate_limits WHERE key = $1 FOR UPDATE`, key).
		Scan(&st.failures, &st.windowStart, &st.blockedUntil); err != nil {
		return ratelimit.Result{}, err
	}
	if st.failures == 0 || l.dead(st, now) {
		st = limitState{windowStart: now, blockedUntil: now}
	}
	st.failures++
	if over := st.failures - l.cfg.Threshold; over >= 0 {
		delay := l.cfg.BaseDelay
		for i := 0; i < over && delay < l.cfg.MaxDelay; i++ {
			delay *= 2
		}
		st.blockedUntil = now.Add(min(delay, l.cfg.MaxDelay))
		// Keep counting while blocked: the window extends to cover the block.
		if end := st.blockedUntil; end.After(st.windowStart.Add(l.cfg.Window)) {
			st.windowStart = end.Add(-l.cfg.Window)
		}
	}
	expires := st.windowStart.Add(l.cfg.Window)
	if st.blockedUntil.After(expires) {
		expires = st.blockedUntil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE iam_rate_limits SET failures = $2, window_start = $3, blocked_until = $4, expires_at = $5
		 WHERE key = $1`, key, st.failures, st.windowStart, st.blockedUntil, expires); err != nil {
		return ratelimit.Result{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ratelimit.Result{}, err
	}
	return l.result(st, now), nil
}

// Reset implements ratelimit.Limiter.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	_, err := l.db.Exec(ctx, `DELETE FROM iam_rate_limits WHERE key = $1`, key)
	return err
}

// PurgeExpired deletes the rows whose window and block ended at or before
// now, and returns how many. Every limiter on the table shares it, so one
// periodic call (for example hourly) is enough.
func (l *Limiter) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	tag, err := l.db.Exec(ctx, `DELETE FROM iam_rate_limits WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
