package iam_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/session"
)

var errStoreDown = errors.New("store down")

// flakyUsers fails LoadSubject while down is set.
type flakyUsers struct {
	iam.UserStore
	down atomic.Bool
}

func (u *flakyUsers) LoadSubject(ctx context.Context, id string) (*iam.Subject, error) {
	if u.down.Load() {
		return nil, errStoreDown
	}
	return u.UserStore.LoadSubject(ctx, id)
}

// flakySessions fails every read while down is set.
type flakySessions struct {
	session.Store
	down atomic.Bool
}

func (s *flakySessions) Get(ctx context.Context, id string) (*session.Session, error) {
	if s.down.Load() {
		return nil, errStoreDown
	}
	return s.Store.Get(ctx, id)
}

func (s *flakySessions) GetByTokenHash(ctx context.Context, hash []byte) (*session.Session, session.TokenState, error) {
	if s.down.Load() {
		return nil, session.TokenState{}, errStoreDown
	}
	return s.Store.GetByTokenHash(ctx, hash)
}

// isUnavailable checks that err reports a store failure, keeps the cause,
// and is not mistaken for an invalid session.
func isUnavailable(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, iam.ErrUnavailable) || !errors.Is(err, errStoreDown) || errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("%s: got %v, want ErrUnavailable wrapping the store error", what, err)
	}
}

func TestSubjectStoreFailureKeepsSession(t *testing.T) {
	var users *flakyUsers
	f := newFixture(t, func(c *iam.Config) {
		users = &flakyUsers{UserStore: c.Users}
		c.Users = users
	})
	cookie, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	if err != nil {
		t.Fatal(err)
	}

	users.down.Store(true)
	_, _, err = f.svc.ValidateSession(ctx, cookie.SessionToken)
	isUnavailable(t, "validate", err)
	_, err = f.svc.RotateSession(ctx, cookie.SessionToken)
	isUnavailable(t, "rotate", err)
	_, err = f.svc.Refresh(ctx, bearer.RefreshToken, iam.ClientInfo{})
	isUnavailable(t, "refresh", err)
	users.down.Store(false)

	// The outage revoked nothing: the cookie session still works, and both
	// sessions are still listed.
	if _, _, err := f.svc.ValidateSession(ctx, cookie.SessionToken); err != nil {
		t.Fatalf("cookie session revoked by a store failure: %v", err)
	}
	if list, _ := f.svc.ListSessions(ctx, "s-admin"); len(list) != 2 {
		t.Fatalf("sessions after outage = %d, want 2", len(list))
	}

	// A subject that is really gone still ends the session.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Disabled: true})
	if _, _, err := f.svc.ValidateSession(ctx, cookie.SessionToken); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("disabled subject: %v", err)
	}
}

func TestSessionStoreFailureIsUnavailable(t *testing.T) {
	var sessions *flakySessions
	f := newFixture(t, func(c *iam.Config) {
		sessions = &flakySessions{Store: c.Sessions}
		c.Sessions = sessions
		c.VerifySessionOnAccess = true
	})
	cookie, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}
	bearer, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	if err != nil {
		t.Fatal(err)
	}

	sessions.down.Store(true)
	_, _, err = f.svc.ValidateSession(ctx, cookie.SessionToken)
	isUnavailable(t, "validate", err)
	_, _, err = f.svc.VerifyAccessToken(ctx, bearer.AccessToken)
	isUnavailable(t, "verify with session check", err)
	_, err = f.svc.Refresh(ctx, bearer.RefreshToken, iam.ClientInfo{})
	isUnavailable(t, "refresh", err)
	isUnavailable(t, "logout", f.svc.Logout(ctx, cookie.SessionToken))
	sessions.down.Store(false)

	if _, _, err := f.svc.ValidateSession(ctx, cookie.SessionToken); err != nil {
		t.Fatalf("after outage: %v", err)
	}
	// Unknown tokens are still invalid, not unavailable.
	if _, _, err := f.svc.ValidateSession(ctx, "garbage"); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("garbage token: %v", err)
	}
}

// Issue #7: a store failure during Refresh must not consume the refresh
// token, so the client can retry without triggering reuse detection.
func TestRefreshStoreFailureKeepsRefreshToken(t *testing.T) {
	var users *flakyUsers
	f := newFixture(t, func(c *iam.Config) {
		users = &flakyUsers{UserStore: c.Users}
		c.Users = users
	})
	res, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	if err != nil {
		t.Fatal(err)
	}

	users.down.Store(true)
	_, err = f.svc.Refresh(ctx, res.RefreshToken, iam.ClientInfo{})
	isUnavailable(t, "refresh during outage", err)
	users.down.Store(false)

	// The retry with the same token succeeds: nothing was rotated.
	pair, err := f.svc.Refresh(ctx, res.RefreshToken, iam.ClientInfo{})
	if err != nil {
		t.Fatalf("retry after outage: %v", err)
	}
	if f.audit.has(audit.EventRefreshReuse) {
		t.Fatal("the retry was treated as refresh-token reuse")
	}
	if list, _ := f.svc.ListSessions(ctx, "s-admin"); len(list) != 1 {
		t.Fatalf("sessions = %d, want 1", len(list))
	}

	// Reuse detection still works for a token that really was rotated.
	if _, err := f.svc.Refresh(ctx, res.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrRefreshReused) {
		t.Fatalf("reuse of rotated token: %v", err)
	}
	if _, err := f.svc.Refresh(ctx, pair.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("session after reuse: %v", err)
	}
}
