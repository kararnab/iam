package iam_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/invite"
	"github.com/kararnab/iam/memstore"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/ratelimit"
	"github.com/kararnab/iam/session"
)

func withInvites(c *iam.Config) {
	c.Signup = iam.SignupConfig{Invites: memstore.NewInvites()}
}

func pwSignup(invite, user, pw string) iam.SignUpRequest {
	return iam.SignUpRequest{
		InviteToken: invite,
		Provider:    password.ProviderName,
		Params:      map[string]string{"username": user, "password": pw},
	}
}

const newPW = "a perfectly fine password"

func TestSignupPolicies(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*iam.Config)
		wantErr error
		roles   []string
	}{
		{"closed by default without an invite store", nil, iam.ErrSignupClosed, nil},
		{"explicitly closed", func(c *iam.Config) {
			c.Signup = iam.SignupConfig{Policy: invite.Closed, Invites: memstore.NewInvites()}
		}, iam.ErrSignupClosed, nil},
		{"invite-only requires an invite", withInvites, iam.ErrInvalidInvite, nil},
		{"open sign-up grants default roles", func(c *iam.Config) {
			c.Signup = iam.SignupConfig{Policy: invite.Open, DefaultRoles: []string{"reader"}}
		}, nil, []string{"reader"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, tt.mutate)
			res, err := f.svc.SignUp(ctx, pwSignup("", "new@example.com", newPW))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && !slices.Equal(res.Subject.Roles, tt.roles) {
				t.Fatalf("roles = %v", res.Subject.Roles)
			}
		})
	}
}

func TestInviteSignup(t *testing.T) {
	f := newFixture(t, withInvites)
	inv, err := f.svc.CreateInvite(ctx, iam.InviteRequest{CreatedBy: "s-admin", Roles: []string{"editor"}})
	if err != nil {
		t.Fatal(err)
	}

	res, err := f.svc.SignUp(ctx, pwSignup(inv.Token, "New@Example.com", newPW))
	if err != nil {
		t.Fatal(err)
	}
	if res.Subject.ID == "" || res.Subject.ID == "s-admin" || !slices.Equal(res.Subject.Roles, []string{"editor"}) {
		t.Fatalf("subject = %+v", res.Subject)
	}
	if res.SessionToken == "" {
		t.Fatal("no session started")
	}
	if !f.audit.has(audit.EventSignup) || !f.audit.has(audit.EventInviteConsumed) || !f.audit.has(audit.EventInviteCreated) {
		t.Fatal("sign-up not audited")
	}

	// The new subject can log in.
	if _, err := f.svc.Login(ctx, pwLogin("new@example.com", newPW, "")); err != nil {
		t.Fatalf("login after sign-up: %v", err)
	}

	// Invites are single-use; the failed attempt leaves no credential behind.
	if _, err := f.svc.SignUp(ctx, pwSignup(inv.Token, "second@example.com", newPW)); !errors.Is(err, iam.ErrInvalidInvite) {
		t.Fatalf("reused invite: %v", err)
	}
	if _, err := f.users.GetCredential(ctx, "second@example.com"); !errors.Is(err, iam.ErrNotFound) {
		t.Fatal("credential created by a failed sign-up")
	}
}

func TestInviteValidation(t *testing.T) {
	clk := time.Unix(1_800_000_000, 0)
	now := func() time.Time { return clk }

	tests := []struct {
		name    string
		req     iam.InviteRequest
		user    string
		advance time.Duration
		token   func(string) string
		wantErr error
	}{
		{"ok", iam.InviteRequest{}, "a@example.com", 0, nil, nil},
		{"expired", iam.InviteRequest{TTL: time.Hour}, "a@example.com", 2 * time.Hour, nil, iam.ErrInvalidInvite},
		{"garbage token", iam.InviteRequest{}, "a@example.com", 0, func(string) string { return "garbage" }, iam.ErrInvalidInvite},
		{"unknown token", iam.InviteRequest{}, "a@example.com", 0, func(string) string { s, _ := session.NewSecret(); return s }, iam.ErrInvalidInvite},
		{"email bound, matches", iam.InviteRequest{Email: "Bound@Example.com"}, "bound@example.com", 0, nil, nil},
		{"email bound, mismatch", iam.InviteRequest{Email: "bound@example.com"}, "other@example.com", 0, nil, iam.ErrInvalidInvite},
		{"weak password", iam.InviteRequest{}, "a@example.com", 0, nil, password.ErrTooShort},
		{"login taken", iam.InviteRequest{}, "admin@example.com", 0, nil, iam.ErrAlreadyRegistered},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clk = time.Unix(1_800_000_000, 0)
			f := newFixture(t, func(c *iam.Config) { withInvites(c); c.Now = now })
			inv, err := f.svc.CreateInvite(ctx, tt.req)
			if err != nil {
				t.Fatal(err)
			}
			clk = clk.Add(tt.advance)
			tok := inv.Token
			if tt.token != nil {
				tok = tt.token(tok)
			}
			pw := newPW
			if tt.wantErr == password.ErrTooShort {
				pw = "short"
			}
			_, err = f.svc.SignUp(ctx, pwSignup(tok, tt.user, pw))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil && tt.user != "admin@example.com" {
				if _, cerr := f.users.GetCredential(ctx, tt.user); !errors.Is(cerr, iam.ErrNotFound) {
					t.Fatal("failed sign-up left a credential behind")
				}
			}
		})
	}
}

func TestInviteRevokedAndConcurrent(t *testing.T) {
	f := newFixture(t, withInvites)
	revoked, _ := f.svc.CreateInvite(ctx, iam.InviteRequest{})
	if err := f.svc.RevokeInvite(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignUp(ctx, pwSignup(revoked.Token, "r@example.com", newPW)); !errors.Is(err, iam.ErrInvalidInvite) {
		t.Fatalf("revoked invite: %v", err)
	}

	inv, _ := f.svc.CreateInvite(ctx, iam.InviteRequest{})
	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			user := string(rune('a'+i)) + "@example.com"
			if _, err := f.svc.SignUp(ctx, pwSignup(inv.Token, user, newPW)); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d sign-ups used one invite", wins)
	}
}

func TestExternalIdentitySignup(t *testing.T) {
	f := newFixture(t, func(c *iam.Config) {
		c.Signup = iam.SignupConfig{Policy: invite.Open, DefaultRoles: []string{"reader"}}
	})
	req := iam.SignUpRequest{Provider: "oidc", Params: map[string]string{"sub": "g-42"}}
	res, err := f.svc.SignUp(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignUp(ctx, req); !errors.Is(err, iam.ErrAlreadyRegistered) {
		t.Fatalf("second sign-up: %v", err)
	}
	again, err := f.svc.Login(ctx, iam.AuthRequest{Provider: "oidc", Params: req.Params})
	if err != nil || again.Subject.ID != res.Subject.ID {
		t.Fatalf("login after external sign-up: %v", err)
	}
}

func TestCreateInviteWithoutStore(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := f.svc.CreateInvite(ctx, iam.InviteRequest{}); err == nil {
		t.Fatal("CreateInvite worked without an invite store")
	}
}

// hooks records lockout callbacks.
type hooks struct {
	mu       sync.Mutex
	failures int
	blocked  []string
}

func (h *hooks) OnFailure(context.Context, string, ratelimit.Result) {
	h.mu.Lock()
	h.failures++
	h.mu.Unlock()
}

func (h *hooks) OnBlocked(_ context.Context, key string, _ ratelimit.Result) {
	h.mu.Lock()
	h.blocked = append(h.blocked, key)
	h.mu.Unlock()
}

func TestLoginRateLimit(t *testing.T) {
	newLimiter := func(threshold int) ratelimit.Limiter {
		l, err := ratelimit.NewMemory(ratelimit.Config{Threshold: threshold, BaseDelay: time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	h := &hooks{}
	f := newFixture(t, func(c *iam.Config) {
		c.RateLimit = iam.RateLimitConfig{PerLogin: newLimiter(3), PerIP: newLimiter(10), Hooks: h}
	})

	// A success resets the per-login counter.
	for range 2 {
		_, _ = f.svc.Login(ctx, pwLogin("admin@example.com", "wrong", ""))
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, "")); err != nil {
		t.Fatalf("login before threshold: %v", err)
	}

	// Three failures block the login, even with the right password.
	for range 3 {
		_, _ = f.svc.Login(ctx, pwLogin("ADMIN@example.com", "wrong", ""))
	}
	_, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, ""))
	var rl *iam.RateLimitError
	if !errors.As(err, &rl) || !errors.Is(err, iam.ErrRateLimited) || rl.RetryAfter <= 0 {
		t.Fatalf("blocked login: %v", err)
	}
	if len(h.blocked) != 1 || h.blocked[0] != "login:password:admin@example.com" || h.failures < 3 {
		t.Fatalf("hooks = %+v", h)
	}
	if !f.audit.has(audit.EventLockout) || !f.audit.has(audit.EventRateLimited) {
		t.Fatal("throttling not audited")
	}

	// Unknown logins are throttled the same way (no user enumeration).
	for range 3 {
		_, _ = f.svc.Login(ctx, pwLogin("ghost@example.com", "wrong", ""))
	}
	if _, err := f.svc.Login(ctx, pwLogin("ghost@example.com", "wrong", "")); !errors.Is(err, iam.ErrRateLimited) {
		t.Fatalf("unknown login not throttled: %v", err)
	}

	// The per-IP limit catches spraying across many logins from one address.
	for i := range 10 {
		_, _ = f.svc.Login(ctx, pwLogin(string(rune('a'+i))+"@example.com", "wrong", ""))
	}
	if _, err := f.svc.Login(ctx, pwLogin("fresh@example.com", "wrong", "")); !errors.Is(err, iam.ErrRateLimited) {
		t.Fatalf("IP not throttled: %v", err)
	}
}
