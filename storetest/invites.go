package storetest

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/session"
)

// ManagedInviteStore is what InviteManager needs.
type ManagedInviteStore interface {
	invite.Store
	invite.Manager
}

// InviteManager runs the invite.Manager conformance tests.
func InviteManager(t *testing.T, newStore func(t *testing.T) ManagedInviteStore) {
	newInvite := func(id string, created, expires time.Time) (*invite.Invite, []byte) {
		_, hash := session.NewSecret()
		return &invite.Invite{
			ID: id, TokenHash: hash, Email: id + "@example.com", Roles: []string{"editor"},
			CreatedBy: "admin", CreatedAt: created, ExpiresAt: expires,
		}, hash
	}
	ids := func(list []*invite.Invite) []string {
		out := make([]string, 0, len(list))
		for _, inv := range list {
			out = append(out, inv.ID)
		}
		return out
	}
	// seed creates: old (usable), new (usable, newest), used, expired.
	seed := func(t *testing.T, s ManagedInviteStore) {
		t.Helper()
		old, _ := newInvite("old", base, base.Add(2*time.Hour))
		recent, _ := newInvite("new", base.Add(time.Minute), base.Add(2*time.Hour))
		used, usedHash := newInvite("used", base, base.Add(2*time.Hour))
		expired, _ := newInvite("expired", base.Add(-2*time.Hour), base.Add(-time.Hour))
		for _, inv := range []*invite.Invite{old, recent, used, expired} {
			if err := s.Create(ctx, inv); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Consume(ctx, usedHash, "password:x", base); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("list usable, newest first", func(t *testing.T) {
		s := newStore(t)
		if list, err := s.ListUsable(ctx, base); err != nil || len(list) != 0 {
			t.Fatalf("empty store = %v, %v", ids(list), err)
		}
		seed(t, s)
		list, err := s.ListUsable(ctx, base)
		if err != nil || !slices.Equal(ids(list), []string{"new", "old"}) {
			t.Fatalf("ListUsable = %v, %v", ids(list), err)
		}
		if got := list[0]; got.Email != "new@example.com" || !slices.Equal(got.Roles, []string{"editor"}) ||
			got.CreatedBy != "admin" || !sameTime(got.ExpiresAt, base.Add(2*time.Hour)) {
			t.Fatalf("listed invite = %+v", got)
		}
		if list, err := s.ListUsable(ctx, base.Add(2*time.Hour)); err != nil || len(list) != 0 {
			t.Fatalf("at expiry = %v, %v", ids(list), err)
		}
	})

	t.Run("delete usable", func(t *testing.T) {
		s := newStore(t)
		seed(t, s)
		if err := s.DeleteUsable(ctx, "old", base); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteUsable(ctx, "old", base); !errors.Is(err, invite.ErrNotFound) {
			t.Fatalf("second delete = %v", err)
		}
		for _, id := range []string{"used", "expired"} {
			if err := s.DeleteUsable(ctx, id, base); !errors.Is(err, invite.ErrInvalid) {
				t.Fatalf("delete %s = %v", id, err)
			}
		}
		// Used and expired invites are kept; only "new" is still listed.
		if list, err := s.ListUsable(ctx, base); err != nil || !slices.Equal(ids(list), []string{"new"}) {
			t.Fatalf("after deletes = %v, %v", ids(list), err)
		}
		if err := s.Delete(ctx, "used"); err != nil {
			t.Fatalf("plain delete of a used invite: %v", err)
		}
	})

	t.Run("replace", func(t *testing.T) {
		s := newStore(t)
		seed(t, s)
		next, nextHash := newInvite("next", base.Add(2*time.Minute), base.Add(3*time.Hour))
		if err := s.Replace(ctx, "old", base, next); err != nil {
			t.Fatal(err)
		}
		if list, err := s.ListUsable(ctx, base); err != nil || !slices.Equal(ids(list), []string{"next", "new"}) {
			t.Fatalf("after replace = %v, %v", ids(list), err)
		}
		if got, err := s.GetByTokenHash(ctx, nextHash); err != nil || got.ID != "next" {
			t.Fatalf("replacement = %+v, %v", got, err)
		}

		// Nothing is created when the old invite can't be replaced.
		for id, wantErr := range map[string]error{"old": invite.ErrNotFound, "used": invite.ErrInvalid, "expired": invite.ErrInvalid} {
			inv, hash := newInvite("for-"+id, base, base.Add(time.Hour))
			if err := s.Replace(ctx, id, base, inv); !errors.Is(err, wantErr) {
				t.Fatalf("replace %s = %v, want %v", id, err, wantErr)
			}
			if _, err := s.GetByTokenHash(ctx, hash); !errors.Is(err, invite.ErrNotFound) {
				t.Fatalf("replace %s created its invite: %v", id, err)
			}
		}
	})

	t.Run("concurrent replacements have one winner", func(t *testing.T) {
		s := newStore(t)
		seed(t, s)
		var mu sync.Mutex
		wins := 0
		var wg sync.WaitGroup
		for i := range 8 {
			wg.Go(func() {
				inv, _ := newInvite(fmt.Sprintf("r-%d", i), base, base.Add(time.Hour))
				if err := s.Replace(ctx, "old", base, inv); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d replacements won", wins)
		}
	})
}
