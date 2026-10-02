// Package storetest is a conformance suite for store implementations.
//
// Every store shipped with the library runs it, and so should yours:
//
//	func TestSessions(t *testing.T) {
//	    storetest.Sessions(t, func(t *testing.T) session.Store { return newMyStore(t) })
//	}
//
// Each factory call must return an empty store.
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/invite"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
)

var ctx = context.Background()

// base is a fixed, microsecond-aligned time (databases often store
// microseconds), well in the future relative to the stores' own clocks.
var base = time.Now().Add(time.Hour).Truncate(time.Second).UTC()

func sameTime(a, b time.Time) bool {
	d := a.Sub(b)
	return d < time.Millisecond && d > -time.Millisecond
}

func newSession(subject string, mode session.Mode) (*session.Session, []byte) {
	_, hash := session.NewSecret()
	return &session.Session{
		ID:         fmt.Sprintf("s-%x-%s", hash[:6], subject),
		SubjectID:  subject,
		Mode:       mode,
		TokenHash:  hash,
		CreatedAt:  base,
		LastUsedAt: base,
		ExpiresAt:  base.Add(24 * time.Hour),
		Attrs:      map[string]string{"ip": "203.0.113.1"},
	}, hash
}

// Sessions runs the session.Store conformance tests.
func Sessions(t *testing.T, newStore func(t *testing.T) session.Store) {
	t.Run("create and get", func(t *testing.T) {
		s := newStore(t)
		sess, hash := newSession("alice", session.ModeCookie)
		if err := s.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
		if err := s.Create(ctx, sess); err == nil {
			t.Fatal("duplicate session ID accepted")
		}
		got, err := s.Get(ctx, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.SubjectID != "alice" || got.Mode != session.ModeCookie || !bytes.Equal(got.TokenHash, hash) ||
			!sameTime(got.CreatedAt, base) || !sameTime(got.ExpiresAt, sess.ExpiresAt) || got.Attrs["ip"] != "203.0.113.1" {
			t.Fatalf("got %+v", got)
		}
		byHash, state, err := s.GetByTokenHash(ctx, hash)
		if err != nil || byHash.ID != sess.ID || !state.RotatedAt.IsZero() {
			t.Fatalf("GetByTokenHash = %+v, %+v, %v", byHash, state, err)
		}
		if _, err := s.Get(ctx, "missing"); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		_, other := session.NewSecret()
		if _, _, err := s.GetByTokenHash(ctx, other); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("unknown hash: %v", err)
		}
	})

	t.Run("rotate", func(t *testing.T) {
		s := newStore(t)
		sess, oldHash := newSession("alice", session.ModeBearer)
		_ = s.Create(ctx, sess)
		_, newHash := session.NewSecret()
		at := base.Add(time.Minute)

		if err := s.Rotate(ctx, sess.ID, oldHash, newHash, at); err != nil {
			t.Fatal(err)
		}
		cur, state, err := s.GetByTokenHash(ctx, newHash)
		if err != nil || cur.ID != sess.ID || !state.RotatedAt.IsZero() || !bytes.Equal(cur.TokenHash, newHash) || !sameTime(cur.LastUsedAt, at) {
			t.Fatalf("new hash: %+v %+v %v", cur, state, err)
		}
		old, state, err := s.GetByTokenHash(ctx, oldHash)
		if err != nil || old.ID != sess.ID || !sameTime(state.RotatedAt, at) {
			t.Fatalf("old hash: %+v %+v %v", old, state, err)
		}

		// The old hash is no longer current.
		_, another := session.NewSecret()
		if err := s.Rotate(ctx, sess.ID, oldHash, another, at); !errors.Is(err, session.ErrConflict) {
			t.Fatalf("stale rotate: %v", err)
		}
		if err := s.Rotate(ctx, "missing", newHash, another, at); !errors.Is(err, session.ErrNotFound) {
			t.Fatalf("rotate missing: %v", err)
		}
	})

	t.Run("concurrent rotate has one winner", func(t *testing.T) {
		s := newStore(t)
		sess, oldHash := newSession("alice", session.ModeBearer)
		_ = s.Create(ctx, sess)
		const n = 10
		var wg sync.WaitGroup
		errs := make(chan error, n)
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, h := session.NewSecret()
				errs <- s.Rotate(ctx, sess.ID, oldHash, h, base)
			}()
		}
		wg.Wait()
		close(errs)
		wins := 0
		for err := range errs {
			switch {
			case err == nil:
				wins++
			case !errors.Is(err, session.ErrConflict):
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("%d concurrent rotations succeeded", wins)
		}
	})

	t.Run("touch", func(t *testing.T) {
		s := newStore(t)
		sess, _ := newSession("alice", session.ModeCookie)
		_ = s.Create(ctx, sess)
		at := base.Add(5 * time.Minute)
		if err := s.Touch(ctx, sess.ID, at); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Get(ctx, sess.ID)
		if !sameTime(got.LastUsedAt, at) {
			t.Fatalf("LastUsedAt = %v", got.LastUsedAt)
		}
	})

	t.Run("delete removes rotated hashes", func(t *testing.T) {
		s := newStore(t)
		sess, oldHash := newSession("alice", session.ModeBearer)
		_ = s.Create(ctx, sess)
		_, newHash := session.NewSecret()
		_ = s.Rotate(ctx, sess.ID, oldHash, newHash, base)
		if err := s.Delete(ctx, sess.ID); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, sess.ID); err != nil {
			t.Fatalf("second delete: %v", err)
		}
		for _, h := range [][]byte{oldHash, newHash} {
			if _, _, err := s.GetByTokenHash(ctx, h); !errors.Is(err, session.ErrNotFound) {
				t.Fatalf("hash survived delete: %v", err)
			}
		}
	})

	t.Run("list and delete by subject", func(t *testing.T) {
		s := newStore(t)
		var ids []string
		for range 3 {
			sess, _ := newSession("alice", session.ModeCookie)
			_ = s.Create(ctx, sess)
			ids = append(ids, sess.ID)
		}
		bob, _ := newSession("bob", session.ModeCookie)
		_ = s.Create(ctx, bob)

		list, err := s.ListBySubject(ctx, "alice")
		if err != nil || len(list) != 3 {
			t.Fatalf("list = %d, %v", len(list), err)
		}
		n, err := s.DeleteBySubject(ctx, "alice", ids[1])
		if err != nil || n != 2 {
			t.Fatalf("DeleteBySubject = %d, %v", n, err)
		}
		list, _ = s.ListBySubject(ctx, "alice")
		if len(list) != 1 || list[0].ID != ids[1] {
			t.Fatalf("after delete: %+v", list)
		}
		if _, err := s.Get(ctx, bob.ID); err != nil {
			t.Fatal("another subject's session was deleted")
		}
		n, _ = s.DeleteBySubject(ctx, "alice", "")
		if n != 1 {
			t.Fatalf("delete all = %d", n)
		}
	})
}

// Invites runs the invite.Store conformance tests.
func Invites(t *testing.T, newStore func(t *testing.T) invite.Store) {
	newInvite := func(id string, expires time.Time) (*invite.Invite, []byte) {
		_, hash := session.NewSecret()
		return &invite.Invite{
			ID: id, TokenHash: hash, Email: "x@example.com", Roles: []string{"editor"},
			CreatedBy: "admin", CreatedAt: base, ExpiresAt: expires,
		}, hash
	}

	t.Run("create, get, consume once", func(t *testing.T) {
		s := newStore(t)
		inv, hash := newInvite("i1", base.Add(time.Hour))
		if err := s.Create(ctx, inv); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetByTokenHash(ctx, hash)
		if err != nil || got.ID != "i1" || got.Email != "x@example.com" || !slices.Equal(got.Roles, []string{"editor"}) || !got.UsedAt.IsZero() {
			t.Fatalf("get = %+v, %v", got, err)
		}
		used, err := s.Consume(ctx, hash, "password:new", base)
		if err != nil || used.UsedBy != "password:new" || !sameTime(used.UsedAt, base) || !slices.Equal(used.Roles, []string{"editor"}) {
			t.Fatalf("consume = %+v, %v", used, err)
		}
		if _, err := s.Consume(ctx, hash, "password:other", base); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("second consume: %v", err)
		}
		_, other := session.NewSecret()
		if _, err := s.GetByTokenHash(ctx, other); !errors.Is(err, invite.ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		if _, err := s.Consume(ctx, other, "x", base); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("consume unknown: %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		s := newStore(t)
		inv, hash := newInvite("i2", base.Add(time.Hour))
		_ = s.Create(ctx, inv)
		if _, err := s.Consume(ctx, hash, "x", base.Add(time.Hour)); !errors.Is(err, invite.ErrInvalid) {
			t.Fatalf("consume at expiry: %v", err)
		}
	})

	t.Run("concurrent consume has one winner", func(t *testing.T) {
		s := newStore(t)
		inv, hash := newInvite("i3", base.Add(time.Hour))
		_ = s.Create(ctx, inv)
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Consume(ctx, hash, "x", base); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d consumers won", wins)
		}
	})

	t.Run("delete", func(t *testing.T) {
		s := newStore(t)
		inv, hash := newInvite("i4", base.Add(time.Hour))
		_ = s.Create(ctx, inv)
		if err := s.Delete(ctx, "i4"); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete(ctx, "i4"); err != nil {
			t.Fatalf("second delete: %v", err)
		}
		if _, err := s.GetByTokenHash(ctx, hash); !errors.Is(err, invite.ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})
}

// UserStore is what Users needs: subjects, identities and credentials.
type UserStore interface {
	iam.UserStore
	password.CredentialStore
}

// Users runs the iam.UserStore and password.CredentialStore conformance tests.
func Users(t *testing.T, newStore func(t *testing.T) UserStore) {
	t.Run("subjects and identities", func(t *testing.T) {
		s := newStore(t)
		g := provider.Identity{Provider: "google", ProviderID: "g-1", Email: "a@example.com"}
		id, err := s.CreateSubject(ctx, g, iam.SignupGrant{Roles: []string{"editor", "reader"}})
		if err != nil || id == "" {
			t.Fatalf("CreateSubject = %q, %v", id, err)
		}
		id2, _ := s.CreateSubject(ctx, g, iam.SignupGrant{})
		if id2 == id {
			t.Fatal("CreateSubject reused an ID")
		}

		sub, err := s.LoadSubject(ctx, id)
		if err != nil || sub.ID != id || !slices.Equal(sub.Roles, []string{"editor", "reader"}) || sub.Disabled {
			t.Fatalf("LoadSubject = %+v, %v", sub, err)
		}
		if _, err := s.LoadSubject(ctx, "missing"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("missing subject: %v", err)
		}

		if _, err := s.ResolveIdentity(ctx, "google", "g-1"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("CreateSubject must not link: %v", err)
		}
		if err := s.LinkIdentity(ctx, id, g); err != nil {
			t.Fatal(err)
		}
		if err := s.LinkIdentity(ctx, id2, g); !errors.Is(err, iam.ErrConflict) {
			t.Fatalf("identity linked twice: %v", err)
		}
		if err := s.LinkIdentity(ctx, "missing", provider.Identity{Provider: "x", ProviderID: "y"}); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("link to missing subject: %v", err)
		}
		if got, err := s.ResolveIdentity(ctx, "google", "g-1"); err != nil || got != id {
			t.Fatalf("resolve = %q, %v", got, err)
		}
		// Identity keys are (provider, providerID), not providerID alone.
		if _, err := s.ResolveIdentity(ctx, "oidc", "g-1"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("resolved across providers: %v", err)
		}

		if err := s.UnlinkIdentity(ctx, id2, "google", "g-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ResolveIdentity(ctx, "google", "g-1"); err != nil {
			t.Fatal("another subject unlinked the identity")
		}
		_ = s.UnlinkIdentity(ctx, id, "google", "g-1")
		if _, err := s.ResolveIdentity(ctx, "google", "g-1"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("after unlink: %v", err)
		}
	})

	t.Run("credentials", func(t *testing.T) {
		s := newStore(t)
		if err := s.CreateCredential(ctx, "a@example.com", "h1"); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateCredential(ctx, "a@example.com", "h2"); !errors.Is(err, iam.ErrConflict) {
			t.Fatalf("duplicate: %v", err)
		}
		if err := s.UpdateCredential(ctx, "missing", "h"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("update missing: %v", err)
		}
		_ = s.UpdateCredential(ctx, "a@example.com", "h3")
		if h, err := s.GetCredential(ctx, "a@example.com"); err != nil || h != "h3" {
			t.Fatalf("get = %q, %v", h, err)
		}
		_ = s.DeleteCredential(ctx, "a@example.com")
		if err := s.DeleteCredential(ctx, "a@example.com"); err != nil {
			t.Fatalf("second delete: %v", err)
		}
		if _, err := s.GetCredential(ctx, "a@example.com"); !errors.Is(err, iam.ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})
}
