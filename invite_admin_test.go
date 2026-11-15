package iam_test

import (
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/provider"
)

// stepClock advances one second per call, so invites get distinct times.
type stepClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(time.Second)
	return c.now
}

func inviteAdmin(t *testing.T, f fixture) iam.InviteAdmin {
	t.Helper()
	a, ok := f.svc.(iam.InviteAdmin)
	if !ok {
		t.Fatal("the default Service does not implement iam.InviteAdmin")
	}
	return a
}

func pendingIDs(list []iam.PendingInvite) []string {
	out := []string{}
	for _, p := range list {
		out = append(out, p.ID)
	}
	return out
}

func TestInviteAdmin(t *testing.T) {
	clk := &stepClock{now: time.Now()}
	f := newFixture(t, func(c *iam.Config) {
		withInvites(c)
		c.Now = clk.Now
	})
	admin := inviteAdmin(t, f)

	first, err := f.svc.CreateInvite(ctx, iam.InviteRequest{CreatedBy: "s-admin", Email: "Ann@Example.com", Roles: []string{"editor"}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.CreateInvite(ctx, iam.InviteRequest{CreatedBy: "s-admin"})
	if err != nil {
		t.Fatal(err)
	}
	used, err := f.svc.CreateInvite(ctx, iam.InviteRequest{CreatedBy: "s-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SignUp(ctx, pwSignup(used.Token, "carol@example.com", newPW)); err != nil {
		t.Fatal(err)
	}

	list, err := admin.ListPendingInvites(ctx)
	if err != nil || !slices.Equal(pendingIDs(list), []string{second.ID, first.ID}) {
		t.Fatalf("ListPendingInvites = %v, %v", pendingIDs(list), err)
	}
	if p := list[1]; p.Email != "ann@example.com" || !slices.Equal(p.Roles, []string{"editor"}) || p.CreatedBy != "s-admin" || !p.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("pending invite = %+v", p)
	}

	t.Run("revoke only while pending", func(t *testing.T) {
		if err := admin.RevokePendingInvite(ctx, used.ID, "s-admin"); !errors.Is(err, iam.ErrInvalidInvite) {
			t.Fatalf("revoke used = %v", err)
		}
		if err := admin.RevokePendingInvite(ctx, "missing", "s-admin"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("revoke missing = %v", err)
		}
		if err := admin.RevokePendingInvite(ctx, second.ID, "s-admin"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.SignUp(ctx, pwSignup(second.Token, "dan@example.com", newPW)); !errors.Is(err, iam.ErrInvalidInvite) {
			t.Fatalf("sign-up with a revoked invite = %v", err)
		}
		if !f.audit.has(audit.EventInviteRevoked) {
			t.Fatal("no invite_revoked audit event")
		}
	})

	t.Run("replace issues a new link and voids the old one", func(t *testing.T) {
		next, err := admin.ReplaceInvite(ctx, first.ID, iam.InviteRequest{CreatedBy: "s-admin", Email: "ann@example.com", Roles: []string{"editor"}})
		if err != nil || next.Token == "" || next.ID == first.ID {
			t.Fatalf("ReplaceInvite = %+v, %v", next, err)
		}
		if list, err := admin.ListPendingInvites(ctx); err != nil || !slices.Equal(pendingIDs(list), []string{next.ID}) {
			t.Fatalf("after replace = %v, %v", pendingIDs(list), err)
		}
		if _, err := f.svc.SignUp(ctx, pwSignup(first.Token, "ann@example.com", newPW)); !errors.Is(err, iam.ErrInvalidInvite) {
			t.Fatalf("old link = %v", err)
		}
		if _, err := f.svc.SignUp(ctx, pwSignup(next.Token, "ann@example.com", newPW)); err != nil {
			t.Fatalf("new link = %v", err)
		}
		// The replaced invite is gone; a used one cannot be replaced.
		if _, err := admin.ReplaceInvite(ctx, first.ID, iam.InviteRequest{}); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("replace again = %v", err)
		}
		if _, err := admin.ReplaceInvite(ctx, next.ID, iam.InviteRequest{}); !errors.Is(err, iam.ErrInvalidInvite) {
			t.Fatalf("replace used = %v", err)
		}
		if _, err := admin.ReplaceInvite(ctx, next.ID, iam.InviteRequest{TTL: -time.Second}); err == nil {
			t.Fatal("replace with a bad TTL worked")
		}
	})
}

// plainInvites hides memstore's invite.Manager methods.
type plainInvites struct{ invite.Store }

func TestInviteAdminNeedsAManager(t *testing.T) {
	for name, mutate := range map[string]func(*iam.Config){
		"no invite store":         nil,
		"store without a Manager": func(c *iam.Config) { c.Signup = iam.SignupConfig{Invites: plainInvites{memstore.NewInvites()}} },
	} {
		t.Run(name, func(t *testing.T) {
			admin := inviteAdmin(t, newFixture(t, mutate))
			if _, err := admin.ListPendingInvites(ctx); !errors.Is(err, iam.ErrInvitesNotManaged) {
				t.Fatalf("ListPendingInvites = %v", err)
			}
			if err := admin.RevokePendingInvite(ctx, "x", ""); !errors.Is(err, iam.ErrInvitesNotManaged) {
				t.Fatalf("RevokePendingInvite = %v", err)
			}
			if _, err := admin.ReplaceInvite(ctx, "x", iam.InviteRequest{}); !errors.Is(err, iam.ErrInvitesNotManaged) {
				t.Fatalf("ReplaceInvite = %v", err)
			}
		})
	}
}

func TestNewServices(t *testing.T) {
	if _, err := iam.NewServices(iam.Config{}); err == nil {
		t.Fatal("NewServices accepted an invalid config")
	}
	users := memstore.NewUsers()
	users.PutSubject(iam.Subject{ID: "s-1"})
	if err := users.LinkIdentity(ctx, "s-1", provider.Identity{Provider: "oidc", ProviderID: "g-1"}); err != nil {
		t.Fatal(err)
	}
	svcs, err := iam.NewServices(iam.Config{
		Providers: []provider.AuthProvider{fakeOIDC{}},
		Users:     users,
		Sessions:  memstore.NewSessions(),
		Policy:    adminOnly{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if svcs.Service == nil || svcs.Recovery == nil || svcs.MFA == nil || svcs.Passwords == nil || svcs.InviteAdmin == nil {
		t.Fatalf("unset field: %+v", svcs)
	}
	// Service methods are promoted; unconfigured features say so.
	if _, err := svcs.Login(ctx, iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "g-1"}}); err != nil {
		t.Fatalf("Login = %v", err)
	}
	if _, err := svcs.Recovery.StartPasswordReset(ctx, iam.PasswordResetRequest{Login: "x"}); !errors.Is(err, iam.ErrRecoveryNotConfigured) {
		t.Fatalf("StartPasswordReset = %v", err)
	}
	if _, err := svcs.MFA.TOTPEnabled(ctx, "s-1"); !errors.Is(err, iam.ErrMFANotConfigured) {
		t.Fatalf("TOTPEnabled = %v", err)
	}
	if _, err := svcs.InviteAdmin.ListPendingInvites(ctx); !errors.Is(err, iam.ErrInvitesNotManaged) {
		t.Fatalf("ListPendingInvites = %v", err)
	}
}
