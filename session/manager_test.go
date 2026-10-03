package session_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/session"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

func newManager(t *testing.T, grace time.Duration) (*session.Manager, *memstore.Sessions, *clock) {
	t.Helper()
	clk := &clock{now: time.Unix(1_800_000_000, 0)}
	store := memstore.NewSessions()
	m, err := session.NewManager(store, session.Config{
		Cookie:     session.Timeouts{Idle: 30 * time.Minute, Absolute: 8 * time.Hour},
		Bearer:     session.Timeouts{Idle: 24 * time.Hour, Absolute: 72 * time.Hour},
		ReuseGrace: grace,
		Now:        clk.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m, store, clk
}

var ctx = context.Background()

func TestSecretsAreNotStored(t *testing.T) {
	m, store, _ := newManager(t, 0)
	s, secret, err := m.Create(ctx, "sub", session.ModeCookie, map[string]string{"ip": "1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Get(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(secret)
	want := sha256.Sum256(raw)
	if !bytes.Equal(stored.TokenHash, want[:]) {
		t.Fatal("stored hash is not SHA-256 of the secret")
	}
	if strings.Contains(stored.ID, secret) || bytes.Contains(stored.TokenHash, raw) {
		t.Fatal("secret leaked into the stored session")
	}
	if s.ID == secret {
		t.Fatal("public session ID equals the secret")
	}
}

func TestValidateCookie(t *testing.T) {
	tests := []struct {
		name    string
		advance []time.Duration // validations happen after each advance
		wantOK  bool
	}{
		{"fresh", []time.Duration{0}, true},
		{"activity keeps it alive", []time.Duration{20 * time.Minute, 20 * time.Minute, 20 * time.Minute}, true},
		{"idle timeout", []time.Duration{31 * time.Minute}, false},
		{"absolute timeout despite activity", repeat(20*time.Minute, 25), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, clk := newManager(t, 0)
			_, secret, _ := m.Create(ctx, "sub", session.ModeCookie, nil)
			var err error
			for _, d := range tt.advance {
				clk.Add(d)
				if _, err = m.Validate(ctx, secret); err != nil {
					break
				}
			}
			if (err == nil) != tt.wantOK {
				t.Fatalf("err = %v, want ok=%v", err, tt.wantOK)
			}
		})
	}
}

func repeat(d time.Duration, n int) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[i] = d
	}
	return out
}

func TestModesAreSeparate(t *testing.T) {
	m, _, _ := newManager(t, 0)
	_, cookie, _ := m.Create(ctx, "sub", session.ModeCookie, nil)
	_, refresh, _ := m.Create(ctx, "sub", session.ModeBearer, nil)
	if _, err := m.Validate(ctx, refresh); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("refresh token accepted as cookie: %v", err)
	}
	if _, _, err := m.Refresh(ctx, cookie); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("cookie accepted as refresh token: %v", err)
	}
}

func TestCookieRotation(t *testing.T) {
	m, _, _ := newManager(t, 0)
	s, old, _ := m.Create(ctx, "sub", session.ModeCookie, nil)
	rs, fresh, err := m.Rotate(ctx, old)
	if err != nil || rs.ID != s.ID {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := m.Validate(ctx, old); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("old cookie still valid: %v", err)
	}
	if _, err := m.Validate(ctx, fresh); err != nil {
		t.Fatalf("new cookie invalid: %v", err)
	}
}

func TestRefreshRotationAndReuse(t *testing.T) {
	tests := []struct {
		name        string
		grace       time.Duration
		reuseAfter  time.Duration
		wantErr     error
		sessionLive bool
	}{
		{"reuse revokes family", 0, time.Second, session.ErrReused, false},
		{"reuse within grace is a race", 5 * time.Second, time.Second, session.ErrRaced, true},
		{"reuse after grace revokes", 5 * time.Second, 10 * time.Second, session.ErrReused, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, _, clk := newManager(t, tt.grace)
			s, rt1, _ := m.Create(ctx, "sub", session.ModeBearer, nil)

			_, rt2, err := m.Refresh(ctx, rt1)
			if err != nil || rt2 == rt1 {
				t.Fatalf("first refresh: %v", err)
			}
			clk.Add(tt.reuseAfter)

			got, _, err := m.Refresh(ctx, rt1)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("reuse err = %v, want %v", err, tt.wantErr)
			}
			if got == nil || got.ID != s.ID {
				t.Fatal("reuse error does not identify the session")
			}

			_, rt3, err := m.Refresh(ctx, rt2)
			if tt.sessionLive != (err == nil) {
				t.Fatalf("refresh with latest token after reuse: err = %v, want live=%v", err, tt.sessionLive)
			}
			if tt.sessionLive && rt3 == "" {
				t.Fatal("no new token")
			}
		})
	}
}

// Concurrent refreshes with the same token: exactly one wins; with no grace
// the others count as reuse and revoke the session.
func TestConcurrentRefresh(t *testing.T) {
	m, _, _ := newManager(t, 0)
	_, rt, _ := m.Create(ctx, "sub", session.ModeBearer, nil)

	const n = 16
	var wg sync.WaitGroup
	results := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := m.Refresh(ctx, rt)
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	ok := 0
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, session.ErrReused), errors.Is(err, session.ErrInvalid):
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d refreshes succeeded, want exactly 1", ok)
	}
}

func TestBearerExpiry(t *testing.T) {
	m, _, clk := newManager(t, 0)
	_, rt, _ := m.Create(ctx, "sub", session.ModeBearer, nil)
	for range 3 { // refreshing every 23h stays within idle, until the 72h absolute limit
		clk.Add(23 * time.Hour)
		var err error
		if _, rt, err = m.Refresh(ctx, rt); err != nil {
			t.Fatalf("refresh: %v", err)
		}
	}
	clk.Add(4 * time.Hour)
	if _, _, err := m.Refresh(ctx, rt); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("refresh past absolute expiry: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	m, _, clk := newManager(t, 0)
	a, aSecret, _ := m.Create(ctx, "alice", session.ModeCookie, nil)
	clk.Add(time.Second)
	b, bRefresh, _ := m.Create(ctx, "alice", session.ModeBearer, nil)
	clk.Add(time.Second)
	c, _, _ := m.Create(ctx, "alice", session.ModeCookie, nil)
	_, bobSecret, _ := m.Create(ctx, "bob", session.ModeCookie, nil)

	list, _ := m.List(ctx, "alice")
	if len(list) != 3 || list[0].ID != a.ID {
		t.Fatalf("list = %d sessions", len(list))
	}

	if err := m.RevokeByID(ctx, "bob", a.ID); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("revoking another subject's session: %v", err)
	}

	// Logout with a rotated refresh token still ends the session.
	_, _, _ = m.Refresh(ctx, bRefresh)
	if s, err := m.Revoke(ctx, bRefresh); err != nil || s == nil || s.ID != b.ID {
		t.Fatalf("revoke via rotated token: %v %v", s, err)
	}
	if s, err := m.Revoke(ctx, "not-a-secret"); err != nil || s != nil {
		t.Fatalf("revoking garbage: %v %v", s, err)
	}

	n, err := m.RevokeAll(ctx, "alice", c.ID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v", n, err)
	}
	if _, err := m.Validate(ctx, aSecret); !errors.Is(err, session.ErrInvalid) {
		t.Fatal("session survived RevokeAll")
	}
	if _, err := m.Get(ctx, c.ID); err != nil {
		t.Fatal("excepted session was revoked")
	}
	if _, err := m.Validate(ctx, bobSecret); err != nil {
		t.Fatal("another subject's session was revoked")
	}
}

func TestListSkipsExpired(t *testing.T) {
	m, _, clk := newManager(t, 0)
	_, _, _ = m.Create(ctx, "sub", session.ModeCookie, nil)
	clk.Add(time.Hour) // past cookie idle timeout
	_, _, _ = m.Create(ctx, "sub", session.ModeBearer, nil)
	list, _ := m.List(ctx, "sub")
	if len(list) != 1 || list[0].Mode != session.ModeBearer {
		t.Fatalf("list = %+v", list)
	}
}

func TestHashSecret(t *testing.T) {
	good, _ := session.NewSecret()
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid", good, true},
		{"empty", "", false},
		{"too short", good[:42], false},
		{"too long", good + "A", false},
		{"padding", good[:42] + "=", false},
		{"std alphabet", strings.Replace(good, good[:1], "+", 1), false},
		{"newline", good[:21] + "\n" + good[22:], false},
		// Only 'A', 'Q', 'g', 'w' end a canonical 32-byte encoding; "B" is valid
		// only if it already was the last character.
		{"non-canonical last char", good[:42] + "B", good[42] == 'B'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := session.HashSecret(tt.in)
			if (err == nil) != tt.ok {
				t.Fatalf("HashSecret err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func FuzzHashSecret(f *testing.F) {
	good, _ := session.NewSecret()
	f.Add(good)
	f.Add("")
	f.Add(strings.Repeat("A", 43))
	f.Add(strings.Repeat("_", 43))
	f.Fuzz(func(t *testing.T, s string) {
		h, err := session.HashSecret(s)
		if err != nil {
			return
		}
		// Accepted secrets are canonical: exactly one spelling per hash.
		raw, derr := base64.RawURLEncoding.Strict().DecodeString(s)
		if derr != nil || base64.RawURLEncoding.EncodeToString(raw) != s || len(h) != sha256.Size {
			t.Fatalf("non-canonical secret accepted: %q", s)
		}
	})
}

func TestInspect(t *testing.T) {
	m, _, clk := newManager(t, 0)
	s, rt1, _ := m.Create(ctx, "sub", session.ModeBearer, nil)
	_, cookie, _ := m.Create(ctx, "sub", session.ModeCookie, nil)

	got, err := m.Inspect(ctx, rt1)
	if err != nil || got.ID != s.ID {
		t.Fatalf("inspect = %+v, %v", got, err)
	}
	// Inspect neither rotates nor touches: the token still refreshes.
	_, rt2, err := m.Refresh(ctx, rt1)
	if err != nil {
		t.Fatalf("refresh after inspect: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"rotated away", rt1},
		{"cookie session", cookie},
		{"garbage", "not-a-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := m.Inspect(ctx, tt.token); !errors.Is(err, session.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
	// Inspecting a rotated token is not reuse: the session survives.
	if _, err := m.Inspect(ctx, rt2); err != nil {
		t.Fatalf("latest token after inspecting a rotated one: %v", err)
	}

	clk.Add(73 * time.Hour)
	if _, err := m.Inspect(ctx, rt2); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("expired: %v", err)
	}
}
