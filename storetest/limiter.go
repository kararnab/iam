package storetest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam/v2/ratelimit"
)

// clock is a settable clock for Limiter, safe for concurrent use.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the clock's time.
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Limiter runs the ratelimit.Limiter conformance tests: the semantics of
// ratelimit.Memory, which every shared limiter must match. newLimiter must
// return a limiter built from cfg (whose Now is a test clock) with no
// recorded failures.
func Limiter(t *testing.T, newLimiter func(t *testing.T, cfg ratelimit.Config) ratelimit.Limiter) {
	cfg := func() (ratelimit.Config, *clock) {
		// Second-aligned, so every store's precision represents it exactly.
		clk := &clock{now: time.Now().Truncate(time.Second)}
		return ratelimit.Config{Threshold: 3, Window: 10 * time.Minute, BaseDelay: time.Second, MaxDelay: 4 * time.Second, Now: clk.Now}, clk
	}
	// Keys are unique per test, for stores that outlive a factory call.
	keyFor := func(t *testing.T, name string) string {
		return fmt.Sprintf("%s/%d/%s", t.Name(), time.Now().UnixNano(), name)
	}
	want := func(t *testing.T, what string, got ratelimit.Result, err error, allowed bool, retry time.Duration, failures int) {
		t.Helper()
		if err != nil || got.Allowed != allowed || got.RetryAfter != retry || got.Failures != failures {
			t.Fatalf("%s = %+v, %v; want allowed=%v retry=%v failures=%d", what, got, err, allowed, retry, failures)
		}
	}

	t.Run("unknown key is allowed", func(t *testing.T) {
		c, _ := cfg()
		l := newLimiter(t, c)
		r, err := l.Check(ctx, keyFor(t, "k"))
		want(t, "check", r, err, true, 0, 0)
	})

	t.Run("blocks at the threshold with a doubling, capped delay", func(t *testing.T) {
		c, _ := cfg()
		l := newLimiter(t, c)
		k := keyFor(t, "k")
		for i := 1; i <= 2; i++ {
			r, err := l.Fail(ctx, k)
			want(t, fmt.Sprintf("fail %d", i), r, err, true, 0, i)
		}
		for i, delay := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second} {
			r, err := l.Fail(ctx, k)
			want(t, fmt.Sprintf("fail %d", i+3), r, err, false, delay, i+3)
			r, err = l.Check(ctx, k)
			want(t, fmt.Sprintf("check after fail %d", i+3), r, err, false, delay, i+3)
		}
	})

	t.Run("the block ends but the window remembers", func(t *testing.T) {
		c, clk := cfg()
		l := newLimiter(t, c)
		k := keyFor(t, "k")
		for range 3 {
			_, _ = l.Fail(ctx, k)
		}
		clk.advance(time.Second)
		r, err := l.Check(ctx, k)
		want(t, "check after the block", r, err, true, 0, 3)
		// The next failure is past the threshold again: a longer block.
		r, err = l.Fail(ctx, k)
		want(t, "fail after the block", r, err, false, 2*time.Second, 4)
	})

	t.Run("failures are forgotten after the window", func(t *testing.T) {
		c, clk := cfg()
		l := newLimiter(t, c)
		k := keyFor(t, "k")
		for range 2 {
			_, _ = l.Fail(ctx, k)
		}
		clk.advance(10 * time.Minute)
		r, err := l.Check(ctx, k)
		want(t, "check after the window", r, err, true, 0, 0)
		r, err = l.Fail(ctx, k)
		want(t, "fail after the window", r, err, true, 0, 1)
	})

	t.Run("reset clears a blocked key; keys are independent", func(t *testing.T) {
		c, _ := cfg()
		l := newLimiter(t, c)
		a, b := keyFor(t, "a"), keyFor(t, "b")
		for range 3 {
			_, _ = l.Fail(ctx, a)
		}
		_, _ = l.Fail(ctx, b)
		if err := l.Reset(ctx, a); err != nil {
			t.Fatal(err)
		}
		r, err := l.Check(ctx, a)
		want(t, "check after reset", r, err, true, 0, 0)
		r, err = l.Check(ctx, b)
		want(t, "other key", r, err, true, 0, 1)
		if err := l.Reset(ctx, keyFor(t, "missing")); err != nil {
			t.Fatalf("reset of a missing key: %v", err)
		}
	})

	t.Run("concurrent failures are all counted", func(t *testing.T) {
		c, _ := cfg()
		c.Threshold = 100
		l := newLimiter(t, c)
		k := keyFor(t, "k")
		var wg sync.WaitGroup
		for range 20 {
			wg.Go(func() {
				if _, err := l.Fail(ctx, k); err != nil {
					t.Error(err)
				}
			})
		}
		wg.Wait()
		r, err := l.Check(ctx, k)
		want(t, "check", r, err, true, 0, 20)
	})
}
