package iam_test

import (
	"errors"
	"testing"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

const changedPW = "an entirely different passphrase"

func passwords(t *testing.T, f fixture) iam.Passwords {
	t.Helper()
	p, ok := f.svc.(iam.Passwords)
	if !ok {
		t.Fatal("the default Service does not implement iam.Passwords")
	}
	return p
}

func changeReq(sessionID, current, next string) iam.ChangePasswordRequest {
	return iam.ChangePasswordRequest{
		SessionID:       sessionID,
		Login:           "Admin@Example.com",
		CurrentPassword: current,
		NewPassword:     next,
		Client:          iam.ClientInfo{IP: "203.0.113.7"},
	}
}

func TestChangePassword(t *testing.T) {
	f := newFixture(t, withRecovery)
	pw := passwords(t, f)

	current, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	if err != nil {
		t.Fatal(err)
	}
	reset, err := recovery(t, f).StartPasswordReset(ctx, iam.PasswordResetRequest{Login: "admin@example.com"})
	if err != nil || reset == nil {
		t.Fatalf("StartPasswordReset = %+v, %v", reset, err)
	}

	if err := pw.ChangePassword(ctx, changeReq(current.Session.ID, adminPW, changedPW)); err != nil {
		t.Fatalf("ChangePassword = %v", err)
	}

	// The caller stays signed in; every other session ends.
	if _, _, err := f.svc.ValidateSession(ctx, current.SessionToken); err != nil {
		t.Fatalf("current session = %v", err)
	}
	if _, _, err := f.svc.ValidateSession(ctx, other.SessionToken); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("other session = %v", err)
	}
	if _, err := f.svc.Refresh(ctx, bearer.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("bearer session = %v", err)
	}
	// An earlier reset link no longer works.
	if _, err := recovery(t, f).CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{Token: reset.Token, NewPassword: resetPW}); !errors.Is(err, iam.ErrInvalidOneTimeToken) {
		t.Fatalf("old reset token = %v", err)
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("old password = %v", err)
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", changedPW, session.ModeCookie)); err != nil {
		t.Fatalf("new password = %v", err)
	}
	if !f.audit.has(audit.EventPasswordChanged) {
		t.Fatal("no password_changed audit event")
	}
}

// A wrong current password counts on the login's own throttle, so the
// change form and the sign-in form share one budget.
func TestChangePasswordSharesTheLoginThrottle(t *testing.T) {
	f := newFixture(t, nil)
	pw := passwords(t, f)
	login, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}

	// A rejected new password is checked first and costs nothing.
	for range 10 {
		if err := pw.ChangePassword(ctx, changeReq(login.Session.ID, "wrong", "short")); !errors.Is(err, password.ErrTooShort) {
			t.Fatalf("short new password = %v", err)
		}
	}
	for i := range 5 {
		if err := pw.ChangePassword(ctx, changeReq(login.Session.ID, "wrong password", changedPW)); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("wrong current password %d = %v", i, err)
		}
	}
	var rl *iam.RateLimitError
	if err := pw.ChangePassword(ctx, changeReq(login.Session.ID, adminPW, changedPW)); !errors.As(err, &rl) {
		t.Fatalf("after 5 failures = %v, want *RateLimitError", err)
	}
	if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); !errors.As(err, &rl) {
		t.Fatalf("login after 5 failed changes = %v, want *RateLimitError", err)
	}
}

func TestChangePasswordRejects(t *testing.T) {
	f := newFixture(t, func(c *iam.Config) { c.Signup = iam.SignupConfig{Policy: invite.Open} })
	pw := passwords(t, f)
	admin, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}
	bob, err := f.svc.SignUp(ctx, pwSignup("", "bob@example.com", newPW))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown session", func(t *testing.T) {
		if err := pw.ChangePassword(ctx, changeReq("nope", adminPW, changedPW)); !errors.Is(err, iam.ErrInvalidSession) {
			t.Fatalf("= %v", err)
		}
	})
	t.Run("another subject's login", func(t *testing.T) {
		// Bob's session, the admin's login and password: refused, and the
		// admin's password is unchanged.
		if err := pw.ChangePassword(ctx, changeReq(bob.Session.ID, adminPW, changedPW)); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("= %v", err)
		}
		if _, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie)); err != nil {
			t.Fatalf("admin password changed: %v", err)
		}
	})
	t.Run("unknown login", func(t *testing.T) {
		req := changeReq(admin.Session.ID, adminPW, changedPW)
		req.Login = "nobody@example.com"
		if err := pw.ChangePassword(ctx, req); !errors.Is(err, iam.ErrInvalidCredentials) {
			t.Fatalf("= %v", err)
		}
	})
	t.Run("disabled subject", func(t *testing.T) {
		f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}, Disabled: true})
		if err := pw.ChangePassword(ctx, changeReq(admin.Session.ID, adminPW, changedPW)); !errors.Is(err, iam.ErrInvalidSession) {
			t.Fatalf("= %v", err)
		}
	})
}

func TestChangePasswordNotConfigured(t *testing.T) {
	svcs, err := iam.NewServices(iam.Config{
		Providers: []provider.AuthProvider{fakeOIDC{}},
		Users:     memstore.NewUsers(),
		Sessions:  memstore.NewSessions(),
		Policy:    adminOnly{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := svcs.Passwords.ChangePassword(ctx, iam.ChangePasswordRequest{}); !errors.Is(err, iam.ErrPasswordsNotConfigured) {
		t.Fatalf("ChangePassword = %v", err)
	}
}
