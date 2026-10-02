package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

var ctx = context.Background()

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newLimiter(t *testing.T, cfg Config) (*Memory, *clock) {
	t.Helper()
	clk := &clock{now: time.Unix(1_800_000_000, 0)}
	cfg.Now = clk.Now
	m, err := NewMemory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return m, clk
}

func TestBackoff(t *testing.T) {
	m, _ := newLimiter(t, Config{Threshold: 3, BaseDelay: time.Second, MaxDelay: 5 * time.Second})
	tests := []struct {
		failure   int
		allowed   bool
		retryWant time.Duration
	}{
		{1, true, 0},
		{2, true, 0},
		{3, false, 1 * time.Second}, // threshold reached
		{4, false, 2 * time.Second},
		{5, false, 4 * time.Second},
		{6, false, 5 * time.Second}, // capped
		{7, false, 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint("failure ", tt.failure), func(t *testing.T) {
			r, err := m.Fail(ctx, "k")
			if err != nil {
				t.Fatal(err)
			}
			if r.Allowed != tt.allowed || r.RetryAfter != tt.retryWant || r.Failures != tt.failure {
				t.Fatalf("result = %+v, want allowed=%v retry=%v", r, tt.allowed, tt.retryWant)
			}
			c, _ := m.Check(ctx, "k")
			if c.Allowed != tt.allowed {
				t.Fatalf("Check disagrees with Fail: %+v", c)
			}
		})
	}
}

func TestBlockExpiresAndWindowResets(t *testing.T) {
	m, clk := newLimiter(t, Config{Threshold: 2, Window: time.Minute, BaseDelay: 10 * time.Second})
	_, _ = m.Fail(ctx, "k")
	r, _ := m.Fail(ctx, "k")
	if r.Allowed {
		t.Fatal("not blocked at threshold")
	}

	clk.now = clk.now.Add(11 * time.Second)
	if r, _ := m.Check(ctx, "k"); !r.Allowed {
		t.Fatalf("still blocked after delay: %+v", r)
	}

	clk.now = clk.now.Add(time.Minute)
	if r, _ := m.Fail(ctx, "k"); r.Failures != 1 || !r.Allowed {
		t.Fatalf("window did not reset: %+v", r)
	}
}

func TestResetAndKeysAreIndependent(t *testing.T) {
	m, _ := newLimiter(t, Config{Threshold: 1})
	_, _ = m.Fail(ctx, "a")
	if r, _ := m.Check(ctx, "b"); !r.Allowed {
		t.Fatal("unrelated key blocked")
	}
	_ = m.Reset(ctx, "a")
	if r, _ := m.Check(ctx, "a"); !r.Allowed || r.Failures != 0 {
		t.Fatalf("after reset: %+v", r)
	}
}

func TestMaxKeysBound(t *testing.T) {
	m, clk := newLimiter(t, Config{MaxKeys: 3})
	for i := range 10 {
		clk.now = clk.now.Add(time.Second)
		_, _ = m.Fail(ctx, fmt.Sprint("k", i))
	}
	if len(m.keys) > 3 {
		t.Fatalf("%d keys kept, want at most 3", len(m.keys))
	}
}

func TestConcurrentFailures(t *testing.T) {
	m, _ := newLimiter(t, Config{Threshold: 1000})
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				_, _ = m.Fail(ctx, "k")
			}
		}()
	}
	wg.Wait()
	if r, _ := m.Check(ctx, "k"); r.Failures != 500 {
		t.Fatalf("failures = %d, want 500", r.Failures)
	}
}

func TestNewMemoryValidates(t *testing.T) {
	bad := []Config{
		{Threshold: -1},
		{BaseDelay: time.Minute, MaxDelay: time.Second},
		{Window: -time.Second},
	}
	for _, c := range bad {
		if _, err := NewMemory(c); err == nil {
			t.Errorf("config %+v accepted", c)
		}
	}
}
