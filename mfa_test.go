package iam_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/mfa"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

var mfaKey = []byte("an MFA sealing key of 32+ bytes!")

// mfaClock is a settable clock shared by the service and the test.
type mfaClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *mfaClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mfaClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type mfaFixture struct {
	fixture
	m      iam.MFA
	store  *memstore.MFA
	clock  *mfaClock
	secret []byte
	codes  []string
}

func newMFAFixture(t *testing.T, mutate func(*iam.Config)) *mfaFixture {
	t.Helper()
	store := memstore.NewMFA()
	clock := &mfaClock{now: time.Unix(1_800_000_000, 0)}
	f := newFixture(t, func(c *iam.Config) {
		c.MFA = iam.MFAConfig{Store: store, Key: mfaKey, Issuer: "Test App"}
		c.Now = clock.Now
		if mutate != nil {
			mutate(c)
		}
	})
	m, ok := f.svc.(iam.MFA)
	if !ok {
		t.Fatal("the default Service does not implement iam.MFA")
	}
	return &mfaFixture{fixture: f, m: m, store: store, clock: clock}
}

// code returns the current TOTP code, after moving to a fresh step so the
// code has not been used.
func (f *mfaFixture) code() string {
	f.clock.advance(mfa.Period)
	return mfa.Code(f.secret, mfa.Step(f.clock.Now()))
}

// enroll enrolls s-admin and keeps the secret and recovery codes.
func (f *mfaFixture) enroll(t *testing.T) {
	t.Helper()
	e, err := f.m.BeginTOTPEnrollment(ctx, "s-admin", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	f.secret, err = mfa.DecodeSecret(e.Secret)
	if err != nil {
		t.Fatal(err)
	}
	f.codes, err = f.m.ConfirmTOTPEnrollment(ctx, "s-admin", f.code())
	if err != nil {
		t.Fatal(err)
	}
}

func (f *mfaFixture) challenge(t *testing.T, mode session.Mode) string {
	t.Helper()
	_, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, mode))
	var req *iam.MFARequiredError
	if !errors.As(err, &req) || !errors.Is(err, iam.ErrMFARequired) || req.Challenge == "" {
		t.Fatalf("Login = %v, want *MFARequiredError", err)
	}
	return req.Challenge
}

func TestMFAEnrollment(t *testing.T) {
	f := newMFAFixture(t, nil)

	if on, err := f.m.TOTPEnabled(ctx, "s-admin"); on || err != nil {
		t.Fatalf("enabled before enrolling = %v, %v", on, err)
	}
	e, err := f.m.BeginTOTPEnrollment(ctx, "s-admin", "admin@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(e.URI, "otpauth://totp/Test%20App:admin@example.com?") || len(e.Secret) != 32 {
		t.Fatalf("enrollment = %+v", e)
	}
	stored, _ := f.store.GetTOTP(ctx, "s-admin")
	if raw, _ := mfa.DecodeSecret(e.Secret); strings.Contains(string(stored.Secret), string(raw)) {
		t.Fatal("the secret is stored unsealed")
	}

	// A pending factor does not affect login.
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); err != nil {
		t.Fatalf("login with a pending factor = %v", err)
	}
	f.secret, _ = mfa.DecodeSecret(e.Secret)
	if _, err := f.m.ConfirmTOTPEnrollment(ctx, "s-admin", "000000"); !errors.Is(err, iam.ErrInvalidMFACode) {
		t.Fatalf("wrong confirmation code = %v", err)
	}
	codes, err := f.m.ConfirmTOTPEnrollment(ctx, "s-admin", f.code())
	if err != nil || len(codes) != mfa.RecoveryCodeCount {
		t.Fatalf("confirm = %v, %v", codes, err)
	}
	if on, _ := f.m.TOTPEnabled(ctx, "s-admin"); !on {
		t.Fatal("not enabled after confirming")
	}
	if _, err := f.m.BeginTOTPEnrollment(ctx, "s-admin", ""); !errors.Is(err, iam.ErrMFAAlreadyEnrolled) {
		t.Fatalf("second enrollment = %v", err)
	}
	if _, err := f.m.ConfirmTOTPEnrollment(ctx, "s-admin", f.code()); !errors.Is(err, iam.ErrMFANotEnrolled) {
		t.Fatalf("confirm without a pending factor = %v", err)
	}
	if !f.audit.has(audit.EventMFAEnrolled) {
		t.Fatal("no mfa_enrolled event")
	}

	if err := f.m.DisableTOTP(ctx, "s-admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); err != nil {
		t.Fatalf("login after disabling = %v", err)
	}
}

func TestMFALogin(t *testing.T) {
	f := newMFAFixture(t, nil)
	f.enroll(t)

	for _, mode := range []session.Mode{session.ModeCookie, session.ModeBearer} {
		t.Run(string(mode), func(t *testing.T) {
			ch := f.challenge(t, mode)
			if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: "123456"}); !errors.Is(err, iam.ErrInvalidMFACode) {
				t.Fatalf("wrong code = %v", err)
			}
			res, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.code()})
			if err != nil || res.Mode != mode || !res.Session.MFA || res.Subject.ID != "s-admin" {
				t.Fatalf("CompleteMFA = %+v, %v", res, err)
			}
			if mode == session.ModeCookie {
				if _, info, err := f.svc.ValidateSession(ctx, res.SessionToken); err != nil || !info.MFA {
					t.Fatalf("session = %+v, %v", info, err)
				}
				// Rotation keeps the flag.
				rotated, err := f.svc.RotateSession(ctx, res.SessionToken)
				if err != nil || !rotated.Session.MFA {
					t.Fatalf("rotated = %+v, %v", rotated, err)
				}
			} else if res.AccessToken == "" || res.RefreshToken == "" {
				t.Fatalf("bearer result = %+v", res)
			}
		})
	}
	if !f.audit.has(audit.EventMFAChallenge) || !f.audit.has(audit.EventMFASuccess) || !f.audit.has(audit.EventMFAFailure) {
		t.Fatal("missing MFA audit events")
	}
}

func TestMFACodeCannotBeReplayed(t *testing.T) {
	f := newMFAFixture(t, nil)
	f.enroll(t)
	code := f.code()
	if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: f.challenge(t, session.ModeCookie), Code: code}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: f.challenge(t, session.ModeCookie), Code: code}); !errors.Is(err, iam.ErrInvalidMFACode) {
		t.Fatalf("replayed code = %v", err)
	}
	// Nor can an earlier step's code be used after a later one.
	earlier := mfa.Code(f.secret, mfa.Step(f.clock.Now())-1)
	if err := f.m.VerifyMFA(ctx, "s-admin", earlier, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidMFACode) {
		t.Fatalf("earlier code = %v", err)
	}
}

func TestMFARecoveryCodes(t *testing.T) {
	f := newMFAFixture(t, nil)
	f.enroll(t)
	ch := f.challenge(t, session.ModeCookie)
	typed := strings.ToUpper(f.codes[0])
	res, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: typed})
	if err != nil || !res.Session.MFA {
		t.Fatalf("recovery code = %+v, %v", res, err)
	}
	if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.codes[0]}); !errors.Is(err, iam.ErrInvalidMFACode) {
		t.Fatalf("reused recovery code = %v", err)
	}
	if !f.audit.has(audit.EventRecoveryCodeUsed) {
		t.Fatal("no recovery-code event")
	}

	fresh, err := f.m.RegenerateRecoveryCodes(ctx, "s-admin")
	if err != nil || len(fresh) != mfa.RecoveryCodeCount {
		t.Fatalf("regenerate = %v, %v", fresh, err)
	}
	if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.codes[1]}); !errors.Is(err, iam.ErrInvalidMFACode) {
		t.Fatalf("old recovery code after regenerating = %v", err)
	}
	if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: fresh[0]}); err != nil {
		t.Fatalf("new recovery code = %v", err)
	}
}

func TestMFAChallengeRules(t *testing.T) {
	f := newMFAFixture(t, nil)
	f.enroll(t)

	t.Run("garbage and tampered challenges", func(t *testing.T) {
		ch := f.challenge(t, session.ModeCookie)
		tampered := []byte(ch)
		tampered[len(tampered)/2] ^= 1
		for _, bad := range []string{"", "x", string(tampered), strings.Repeat("A", 2000)} {
			if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: bad, Code: f.code()}); !errors.Is(err, iam.ErrInvalidMFACode) {
				t.Fatalf("%.20q: %v", bad, err)
			}
		}
	})
	t.Run("expired challenge", func(t *testing.T) {
		ch := f.challenge(t, session.ModeCookie)
		f.clock.advance(5 * time.Minute)
		if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.code()}); !errors.Is(err, iam.ErrInvalidMFACode) {
			t.Fatalf("expired = %v", err)
		}
	})
	t.Run("challenge from another key", func(t *testing.T) {
		other := newMFAFixture(t, func(c *iam.Config) { c.MFA.Key = []byte("a different key, also 32 bytes!!") })
		other.enroll(t)
		ch := other.challenge(t, session.ModeCookie)
		if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.code()}); !errors.Is(err, iam.ErrInvalidMFACode) {
			t.Fatalf("foreign challenge = %v", err)
		}
	})
	t.Run("disabled subject", func(t *testing.T) {
		ch := f.challenge(t, session.ModeCookie)
		f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}, Disabled: true})
		defer f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}})
		if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.code()}); !errors.Is(err, iam.ErrInvalidMFACode) {
			t.Fatalf("disabled = %v", err)
		}
	})
}

func TestMFAThrottled(t *testing.T) {
	f := newMFAFixture(t, nil)
	f.enroll(t)
	ch := f.challenge(t, session.ModeCookie)
	var rl *iam.RateLimitError
	for i := range 10 {
		_, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: "000000"})
		if errors.As(err, &rl) {
			if i < 5 {
				t.Fatalf("throttled after %d attempts", i)
			}
			// Even the right code is refused while throttled.
			if _, err := f.m.CompleteMFA(ctx, iam.MFARequest{Challenge: ch, Code: f.code()}); !errors.As(err, &rl) {
				t.Fatalf("right code while throttled = %v", err)
			}
			return
		}
	}
	t.Fatal("wrong codes were never throttled")
}

func TestMFAExemptProviderAndStepUp(t *testing.T) {
	f := newMFAFixture(t, func(c *iam.Config) { c.MFA.ExemptProviders = []string{"oidc"} })
	f.enroll(t)
	if err := f.svc.LinkIdentity(ctx, "s-admin", iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "admin-at-idp"}}); err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.Login(ctx, iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "admin-at-idp"}})
	if err != nil || res.Session.MFA {
		t.Fatalf("exempt provider = %+v, %v", res, err)
	}

	if err := f.m.VerifyMFA(ctx, "s-admin", "000000", iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidMFACode) {
		t.Fatalf("step-up with a wrong code = %v", err)
	}
	if err := f.m.VerifyMFA(ctx, "s-admin", f.code(), iam.ClientInfo{}); err != nil {
		t.Fatalf("step-up = %v", err)
	}
}

func TestMFAConfig(t *testing.T) {
	f := newFixture(t, nil)
	m := f.svc.(iam.MFA)
	if _, err := m.BeginTOTPEnrollment(ctx, "s-admin", ""); !errors.Is(err, iam.ErrMFANotConfigured) {
		t.Fatalf("not configured = %v", err)
	}
	for name, c := range map[string]iam.MFAConfig{
		"short key":  {Key: []byte("short"), Issuer: "x"},
		"no issuer":  {Key: mfaKey},
		"long TTL":   {Key: mfaKey, Issuer: "x", ChallengeTTL: time.Hour},
		"large skew": {Key: mfaKey, Issuer: "x", Skew: 3},
	} {
		c.Store = memstore.NewMFA()
		cfg := c
		if _, err := iam.New(iam.Config{
			Providers: []provider.AuthProvider{fakeOIDC{}}, Users: f.users, Sessions: memstore.NewSessions(), Policy: adminOnly{}, MFA: cfg,
		}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
