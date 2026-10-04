package iam_test

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

const resetPW = "a brand new passphrase"

func withRecovery(c *iam.Config) { c.Recovery.Tokens = memstore.NewTokens() }

func recovery(t *testing.T, f fixture) iam.Recovery {
	t.Helper()
	rec, ok := f.svc.(iam.Recovery)
	if !ok {
		t.Fatal("the default Service does not implement iam.Recovery")
	}
	return rec
}

func TestRecoveryNotConfigured(t *testing.T) {
	f := newFixture(t, nil)
	rec := recovery(t, f)
	if _, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: "admin@example.com"}); !errors.Is(err, iam.ErrRecoveryNotConfigured) {
		t.Fatalf("StartPasswordReset = %v", err)
	}
	if _, err := rec.CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{}); !errors.Is(err, iam.ErrRecoveryNotConfigured) {
		t.Fatalf("CompletePasswordReset = %v", err)
	}
	if _, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{SubjectID: "s-admin", Email: "a@b.c"}); !errors.Is(err, iam.ErrRecoveryNotConfigured) {
		t.Fatalf("StartEmailVerification = %v", err)
	}
	if _, err := rec.CompleteEmailVerification(ctx, "x", iam.ClientInfo{}); !errors.Is(err, iam.ErrRecoveryNotConfigured) {
		t.Fatalf("CompleteEmailVerification = %v", err)
	}
}

func TestRecoveryConfigValidation(t *testing.T) {
	users := memstore.NewUsers()
	hasher, _ := password.NewArgon2id(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, 0)
	pwProv, _ := password.NewProvider(users, hasher, password.Policy{})
	cases := map[string]iam.RecoveryConfig{
		"unknown provider":    {PasswordProvider: "nope"},
		"provider cannot set": {PasswordProvider: "oidc"},
		"reset TTL too long":  {ResetTTL: 25 * time.Hour},
		"verify TTL negative": {VerificationTTL: -time.Second},
	}
	for name, rc := range cases {
		t.Run(name, func(t *testing.T) {
			rc.Tokens = memstore.NewTokens()
			_, err := iam.New(iam.Config{
				Providers: []provider.AuthProvider{pwProv, fakeOIDC{}},
				Users:     users,
				Sessions:  memstore.NewSessions(),
				Policy:    adminOnly{},
				Recovery:  rc,
			})
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPasswordReset(t *testing.T) {
	f := newFixture(t, withRecovery)
	rec := recovery(t, f)

	login, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: " ADMIN@example.com "})
	if err != nil || issued == nil {
		t.Fatalf("StartPasswordReset = %+v, %v", issued, err)
	}
	if issued.SubjectID != "s-admin" || issued.Login != "admin@example.com" || issued.Token == "" || !issued.ExpiresAt.After(time.Now()) {
		t.Fatalf("issued = %+v", issued)
	}
	if b, _ := json.Marshal(issued); strings.Contains(string(b), issued.Token) {
		t.Fatalf("IssuedToken JSON contains the secret: %s", b)
	}

	// A rejected password does not use up the token.
	if _, err := rec.CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{Token: issued.Token, NewPassword: "short"}); !errors.Is(err, password.ErrTooShort) {
		t.Fatalf("short password = %v", err)
	}
	subjectID, err := rec.CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{Token: issued.Token, NewPassword: resetPW})
	if err != nil || subjectID != "s-admin" {
		t.Fatalf("CompletePasswordReset = %q, %v", subjectID, err)
	}
	if _, err := rec.CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{Token: issued.Token, NewPassword: resetPW}); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
		t.Fatalf("second use = %v", err)
	}

	// Sessions are revoked, the old password fails and the new one works.
	if _, _, err := f.svc.ValidateSession(ctx, login.SessionToken); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("old session = %v", err)
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("old password = %v", err)
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", resetPW, session.ModeCookie)); err != nil {
		t.Fatalf("new password = %v", err)
	}
	if !f.audit.has(audit.EventPasswordResetRequested) || !f.audit.has(audit.EventPasswordReset) {
		t.Fatal("missing audit events")
	}
}

func TestPasswordResetDoesNotRevealLogins(t *testing.T) {
	f := newFixture(t, withRecovery)
	rec := recovery(t, f)
	for _, login := range []string{"nobody@example.com", "", "   "} {
		issued, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: login})
		if issued != nil || err != nil {
			t.Fatalf("%q: %+v, %v", login, issued, err)
		}
	}

	// A disabled subject gets nothing either.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}, Disabled: true})
	if issued, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: "admin@example.com"}); issued != nil || err != nil {
		t.Fatalf("disabled: %+v, %v", issued, err)
	}
}

func TestPasswordResetTokenRules(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	f := newFixture(t, func(c *iam.Config) { withRecovery(c); c.Now = clock })
	rec := recovery(t, f)
	start := func() string {
		t.Helper()
		issued, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: "admin@example.com"})
		if err != nil || issued == nil {
			t.Fatalf("start = %+v, %v", issued, err)
		}
		return issued.Token
	}
	complete := func(tok string) error {
		_, err := rec.CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{Token: tok, NewPassword: resetPW})
		return err
	}

	t.Run("garbage", func(t *testing.T) {
		for _, tok := range []string{"", "x", strings.Repeat("A", 43)} {
			if err := complete(tok); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
				t.Fatalf("%q: %v", tok, err)
			}
		}
	})
	t.Run("a new request supersedes the old one", func(t *testing.T) {
		first := start()
		second := start()
		if err := complete(first); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
			t.Fatalf("first token = %v", err)
		}
		if err := complete(second); err != nil {
			t.Fatalf("second token = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		tok := start()
		now = now.Add(time.Hour)
		if err := complete(tok); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
			t.Fatalf("expired = %v", err)
		}
	})
	t.Run("verification token is not a reset token", func(t *testing.T) {
		issued, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{SubjectID: "s-admin", Email: "admin@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err := complete(issued.Token); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
			t.Fatalf("verification token used for reset = %v", err)
		}
	})
	t.Run("disabled after the request", func(t *testing.T) {
		tok := start()
		f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}, Disabled: true})
		defer f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}})
		if err := complete(tok); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
			t.Fatalf("disabled = %v", err)
		}
	})
	t.Run("concurrent completions have one winner", func(t *testing.T) {
		tok := start()
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if complete(tok) == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d completions won", wins)
		}
	})
}

func TestPasswordResetThrottled(t *testing.T) {
	f := newFixture(t, withRecovery)
	rec := recovery(t, f)
	var rl *iam.RateLimitError
	for i := range 10 {
		_, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: "nobody@example.com", Client: iam.ClientInfo{IP: "198.51.100.9"}})
		if errors.As(err, &rl) {
			if i < 5 {
				t.Fatalf("throttled after %d requests", i)
			}
			// Logins are not affected.
			if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); err != nil {
				t.Fatalf("login after reset throttling = %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("reset requests were never throttled")
}

func TestEmailVerification(t *testing.T) {
	f := newFixture(t, withRecovery)
	rec := recovery(t, f)

	for _, bad := range []string{"", "no-at-sign", "a@", "@b", "a b@c.d", "a@b@c"} {
		if _, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{SubjectID: "s-admin", Email: bad}); !errors.Is(err, iam.ErrInvalidEmail) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	if _, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{SubjectID: "missing", Email: "a@b.c"}); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("missing subject = %v", err)
	}

	first, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{SubjectID: "s-admin", Email: "Old@Example.com"})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{SubjectID: "s-admin", Email: "New@Example.com"})
	if err != nil || issued.Email != "new@example.com" {
		t.Fatalf("start = %+v, %v", issued, err)
	}
	if _, err := rec.CompleteEmailVerification(ctx, first.Token, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
		t.Fatalf("superseded token = %v", err)
	}
	got, err := rec.CompleteEmailVerification(ctx, issued.Token, iam.ClientInfo{})
	if err != nil || got.SubjectID != "s-admin" || got.Email != "new@example.com" {
		t.Fatalf("complete = %+v, %v", got, err)
	}
	if _, err := rec.CompleteEmailVerification(ctx, issued.Token, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
		t.Fatalf("second use = %v", err)
	}
	if !f.audit.has(audit.EventEmailVerificationRequested) || !f.audit.has(audit.EventEmailVerified) {
		t.Fatal("missing audit events")
	}
}
