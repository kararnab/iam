package memstore

import (
	"context"
	"errors"
	"testing"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/provider"
)

func TestUsersIdentities(t *testing.T) {
	ctx := context.Background()
	u := NewUsers()
	u.PutSubject(iam.Subject{ID: "s1", Roles: []string{"admin"}})
	g := provider.Identity{Provider: "google", ProviderID: "g-1"}

	tests := []struct {
		name    string
		op      func() error
		wantErr error
	}{
		{"link", func() error { return u.LinkIdentity(ctx, "s1", g) }, nil},
		{"link again", func() error { return u.LinkIdentity(ctx, "s1", g) }, iam.ErrConflict},
		{"link to missing subject", func() error {
			return u.LinkIdentity(ctx, "nope", provider.Identity{Provider: "x", ProviderID: "y"})
		}, iam.ErrNotFound},
		{"resolve", func() error {
			id, err := u.ResolveIdentity(ctx, "google", "g-1")
			if err == nil && id != "s1" {
				return errors.New("wrong subject")
			}
			return err
		}, nil},
		{"resolve unknown", func() error { _, err := u.ResolveIdentity(ctx, "google", "g-2"); return err }, iam.ErrNotFound},
		{"unlink by other subject is a no-op", func() error {
			_ = u.UnlinkIdentity(ctx, "s2", "google", "g-1")
			_, err := u.ResolveIdentity(ctx, "google", "g-1")
			return err
		}, nil},
		{"unlink", func() error {
			_ = u.UnlinkIdentity(ctx, "s1", "google", "g-1")
			_, err := u.ResolveIdentity(ctx, "google", "g-1")
			return err
		}, iam.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.op(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestUsersSubjectsAreCopies(t *testing.T) {
	ctx := context.Background()
	u := NewUsers()
	id, err := u.CreateSubject(ctx, provider.Identity{}, iam.SignupGrant{Roles: []string{"reader"}})
	if err != nil || id == "" {
		t.Fatal(err)
	}
	s, _ := u.LoadSubject(ctx, id)
	s.Roles[0] = "admin" // must not leak into the store
	again, _ := u.LoadSubject(ctx, id)
	if again.Roles[0] != "reader" {
		t.Fatal("LoadSubject returned shared state")
	}
	if _, err := u.LoadSubject(ctx, "missing"); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("missing subject: %v", err)
	}
}

func TestUsersCredentials(t *testing.T) {
	ctx := context.Background()
	u := NewUsers()
	if err := u.CreateCredential(ctx, "a", "h1"); err != nil {
		t.Fatal(err)
	}
	if err := u.CreateCredential(ctx, "a", "h2"); !errors.Is(err, iam.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := u.UpdateCredential(ctx, "b", "h"); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("update missing: %v", err)
	}
	_ = u.UpdateCredential(ctx, "a", "h3")
	if h, _ := u.GetCredential(ctx, "a"); h != "h3" {
		t.Fatalf("hash = %q", h)
	}
	_ = u.DeleteCredential(ctx, "a")
	if _, err := u.GetCredential(ctx, "a"); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
