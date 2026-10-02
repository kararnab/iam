package redisstore

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kararnab/iam/ratelimit"
)

// Limiter implements ratelimit.Limiter on Redis, so throttling is shared by
// every instance. It has the same semantics as ratelimit.Memory: after
// Threshold failures within Window the key is blocked for BaseDelay,
// doubling per further failure up to MaxDelay.
type Limiter struct {
	rdb    redis.UniversalClient
	prefix string
	cfg    ratelimit.Config
}

var _ ratelimit.Limiter = (*Limiter)(nil)

// NewLimiter returns a Redis limiter. Zero config values take the
// ratelimit defaults; MaxKeys is ignored (keys expire on their own).
func NewLimiter(rdb redis.UniversalClient, prefix string, cfg ratelimit.Config) (*Limiter, error) {
	if prefix == "" {
		prefix = "{iam}:"
	}
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
		return nil, errors.New("redisstore: invalid limiter config")
	}
	return &Limiter{rdb: rdb, prefix: prefix + "rl:", cfg: cfg}, nil
}

// The hash holds: f = failures, w = window start (ms), b = blocked until (ms).
var limiterScript = redis.NewScript(`
-- KEYS: key   ARGV: mode(check|fail), nowMs, windowMs, threshold, baseMs, maxMs
local now = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local f = tonumber(redis.call('HGET', KEYS[1], 'f') or '0')
local w = tonumber(redis.call('HGET', KEYS[1], 'w') or '0')
local b = tonumber(redis.call('HGET', KEYS[1], 'b') or '0')
if f > 0 and now >= w + window and now >= b then
  redis.call('DEL', KEYS[1]); f = 0; w = 0; b = 0
end
if ARGV[1] == 'fail' then
  if f == 0 then w = now end
  f = f + 1
  local over = f - tonumber(ARGV[4])
  if over >= 0 then
    local delay = tonumber(ARGV[5])
    local maxd = tonumber(ARGV[6])
    local i = 0
    while i < over and delay < maxd do delay = delay * 2; i = i + 1 end
    if delay > maxd then delay = maxd end
    b = now + delay
    if b > w + window then w = b - window end
  end
  redis.call('HSET', KEYS[1], 'f', f, 'w', w, 'b', b)
  redis.call('PEXPIREAT', KEYS[1], math.max(w + window, b) + 1000)
end
return {f, b}
`)

func (l *Limiter) run(ctx context.Context, mode, key string) (ratelimit.Result, error) {
	now := l.cfg.Now()
	res, err := limiterScript.Run(ctx, l.rdb, []string{l.prefix + key}, mode,
		now.UnixMilli(), l.cfg.Window.Milliseconds(), l.cfg.Threshold,
		l.cfg.BaseDelay.Milliseconds(), l.cfg.MaxDelay.Milliseconds()).Int64Slice()
	if err != nil {
		return ratelimit.Result{}, err
	}
	r := ratelimit.Result{Allowed: true, Failures: int(res[0])}
	if until := time.UnixMilli(res[1]); now.Before(until) {
		r.Allowed, r.RetryAfter = false, until.Sub(now)
	}
	return r, nil
}

// Check implements ratelimit.Limiter.
func (l *Limiter) Check(ctx context.Context, key string) (ratelimit.Result, error) {
	return l.run(ctx, "check", key)
}

// Fail implements ratelimit.Limiter.
func (l *Limiter) Fail(ctx context.Context, key string) (ratelimit.Result, error) {
	return l.run(ctx, "fail", key)
}

// Reset implements ratelimit.Limiter.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	return l.rdb.Del(ctx, l.prefix+key).Err()
}
