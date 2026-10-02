package redisstore

import (
	"context"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/kararnab/iam/v2/ratelimit"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/storetest"
)

// newClient connects to IAM_TEST_REDIS_ADDR. Without it the tests are
// skipped. Each test gets its own key prefix.
func newClient(t *testing.T) (redis.UniversalClient, string) {
	t.Helper()
	addr := os.Getenv("IAM_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("IAM_TEST_REDIS_ADDR not set")
	}
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	return rdb, "{iamtest-" + rand.Text()[:8] + "}:"
}

func TestSessionsConformance(t *testing.T) {
	storetest.Sessions(t, func(t *testing.T) session.Store {
		rdb, prefix := newClient(t)
		return NewSessions(rdb, prefix)
	})
}

func TestSessionKeysExpire(t *testing.T) {
	rdb, prefix := newClient(t)
	s := NewSessions(rdb, prefix)
	_, hash := session.NewSecret()
	sess := &session.Session{ID: "s1", SubjectID: "u", Mode: session.ModeCookie, TokenHash: hash,
		CreatedAt: time.Now(), LastUsedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{s.sessKey("s1"), s.tokKey(hash)} {
		ttl := rdb.PTTL(context.Background(), k).Val()
		if ttl <= 0 || ttl > time.Hour {
			t.Fatalf("%s TTL = %v", k, ttl)
		}
	}
}

func TestLimiter(t *testing.T) {
	ctx := context.Background()
	rdb, prefix := newClient(t)
	now := time.Unix(1_800_000_000, 0)
	l, err := NewLimiter(rdb, prefix, ratelimit.Config{
		Threshold: 3, Window: time.Minute, BaseDelay: time.Second, MaxDelay: 5 * time.Second,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		failure int
		allowed bool
		retry   time.Duration
	}{
		{1, true, 0}, {2, true, 0}, {3, false, time.Second}, {4, false, 2 * time.Second},
		{5, false, 4 * time.Second}, {6, false, 5 * time.Second},
	}
	for _, tt := range tests {
		r, err := l.Fail(ctx, "k")
		if err != nil {
			t.Fatal(err)
		}
		if r.Failures != tt.failure || r.Allowed != tt.allowed || r.RetryAfter != tt.retry {
			t.Fatalf("failure %d: %+v", tt.failure, r)
		}
	}
	if r, _ := l.Check(ctx, "other"); !r.Allowed {
		t.Fatal("unrelated key blocked")
	}

	now = now.Add(6 * time.Second)
	if r, _ := l.Check(ctx, "k"); !r.Allowed {
		t.Fatalf("still blocked after delay: %+v", r)
	}
	now = now.Add(2 * time.Minute)
	if r, _ := l.Fail(ctx, "k"); r.Failures != 1 {
		t.Fatalf("window did not reset: %+v", r)
	}
	_ = l.Reset(ctx, "k")
	if r, _ := l.Check(ctx, "k"); r.Failures != 0 {
		t.Fatalf("after reset: %+v", r)
	}
}
