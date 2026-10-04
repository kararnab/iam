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

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/mfa"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/passkey"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
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

// Tokens runs the onetime.Store conformance tests.
func Tokens(t *testing.T, newStore func(t *testing.T) onetime.Store) {
	newToken := func(id, subject string, purpose onetime.Purpose) (*onetime.Token, []byte) {
		_, hash := session.NewSecret()
		return &onetime.Token{
			ID: id, TokenHash: hash, Purpose: purpose, SubjectID: subject,
			Login: "ana@example.com", Email: "ana@example.com",
			CreatedAt: base, ExpiresAt: base.Add(time.Hour),
		}, hash
	}

	t.Run("create, get, consume once", func(t *testing.T) {
		s := newStore(t)
		tok, hash := newToken("t1", "alice", onetime.PasswordReset)
		if err := s.Create(ctx, tok); err != nil {
			t.Fatal(err)
		}
		if err := s.Create(ctx, tok); err == nil {
			t.Fatal("duplicate token accepted")
		}
		got, err := s.GetByTokenHash(ctx, hash)
		if err != nil || got.ID != "t1" || got.SubjectID != "alice" || got.Purpose != onetime.PasswordReset ||
			got.Login != "ana@example.com" || got.Email != "ana@example.com" || !bytes.Equal(got.TokenHash, hash) ||
			!sameTime(got.CreatedAt, base) || !sameTime(got.ExpiresAt, tok.ExpiresAt) || !got.UsedAt.IsZero() {
			t.Fatalf("get = %+v, %v", got, err)
		}
		if _, err := s.Consume(ctx, hash, onetime.EmailVerification, base); !errors.Is(err, onetime.ErrInvalid) {
			t.Fatalf("consume for another purpose: %v", err)
		}
		used, err := s.Consume(ctx, hash, onetime.PasswordReset, base)
		if err != nil || used.ID != "t1" || used.Login != "ana@example.com" || !sameTime(used.UsedAt, base) {
			t.Fatalf("consume = %+v, %v", used, err)
		}
		if _, err := s.Consume(ctx, hash, onetime.PasswordReset, base); !errors.Is(err, onetime.ErrInvalid) {
			t.Fatalf("second consume: %v", err)
		}
		if got, err := s.GetByTokenHash(ctx, hash); err != nil || got.UsedAt.IsZero() {
			t.Fatalf("get after consume = %+v, %v", got, err)
		}
		_, other := session.NewSecret()
		if _, err := s.GetByTokenHash(ctx, other); !errors.Is(err, onetime.ErrNotFound) {
			t.Fatalf("unknown: %v", err)
		}
		if _, err := s.Consume(ctx, other, onetime.PasswordReset, base); !errors.Is(err, onetime.ErrInvalid) {
			t.Fatalf("consume unknown: %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		s := newStore(t)
		tok, hash := newToken("t2", "alice", onetime.EmailVerification)
		_ = s.Create(ctx, tok)
		if _, err := s.Consume(ctx, hash, onetime.EmailVerification, base.Add(time.Hour)); !errors.Is(err, onetime.ErrInvalid) {
			t.Fatalf("consume at expiry: %v", err)
		}
	})

	t.Run("concurrent consume has one winner", func(t *testing.T) {
		s := newStore(t)
		tok, hash := newToken("t3", "alice", onetime.PasswordReset)
		_ = s.Create(ctx, tok)
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Consume(ctx, hash, onetime.PasswordReset, base); err == nil {
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

	t.Run("delete by subject and purpose", func(t *testing.T) {
		s := newStore(t)
		reset, resetHash := newToken("t4", "alice", onetime.PasswordReset)
		verify, verifyHash := newToken("t5", "alice", onetime.EmailVerification)
		bob, bobHash := newToken("t6", "bob", onetime.PasswordReset)
		for _, tok := range []*onetime.Token{reset, verify, bob} {
			if err := s.Create(ctx, tok); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.DeleteBySubject(ctx, "alice", onetime.PasswordReset); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteBySubject(ctx, "nobody", onetime.PasswordReset); err != nil {
			t.Fatalf("delete for unknown subject: %v", err)
		}
		if _, err := s.GetByTokenHash(ctx, resetHash); !errors.Is(err, onetime.ErrNotFound) {
			t.Fatalf("deleted token: %v", err)
		}
		if _, err := s.GetByTokenHash(ctx, verifyHash); err != nil {
			t.Fatalf("other purpose deleted: %v", err)
		}
		if _, err := s.GetByTokenHash(ctx, bobHash); err != nil {
			t.Fatalf("other subject deleted: %v", err)
		}
	})
}

// MFA runs the mfa.Store conformance tests.
func MFA(t *testing.T, newStore func(t *testing.T) mfa.Store) {
	h := mfa.HashRecoveryCode
	factor := func(subject string) *mfa.TOTP {
		return &mfa.TOTP{
			SubjectID: subject, Secret: []byte("sealed-secret"), Confirmed: true, LastStep: 100,
			RecoveryCodes: [][]byte{h("aaaaa-aaaaa"), h("bbbbb-bbbbb")}, CreatedAt: base,
		}
	}

	t.Run("put, get, replace, delete", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.GetTOTP(ctx, "alice"); !errors.Is(err, mfa.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		pending := &mfa.TOTP{SubjectID: "alice", Secret: []byte("pending"), CreatedAt: base}
		if err := s.PutTOTP(ctx, pending); err != nil {
			t.Fatal(err)
		}
		got, err := s.GetTOTP(ctx, "alice")
		if err != nil || got.Confirmed || string(got.Secret) != "pending" || len(got.RecoveryCodes) != 0 || !sameTime(got.CreatedAt, base) {
			t.Fatalf("pending = %+v, %v", got, err)
		}
		if err := s.PutTOTP(ctx, factor("alice")); err != nil {
			t.Fatalf("replace: %v", err)
		}
		got, err = s.GetTOTP(ctx, "alice")
		if err != nil || !got.Confirmed || string(got.Secret) != "sealed-secret" || got.LastStep != 100 ||
			len(got.RecoveryCodes) != 2 || !bytes.Equal(got.RecoveryCodes[1], h("bbbbb-bbbbb")) {
			t.Fatalf("confirmed = %+v, %v", got, err)
		}
		if err := s.DeleteTOTP(ctx, "alice"); err != nil {
			t.Fatal(err)
		}
		if err := s.DeleteTOTP(ctx, "alice"); err != nil {
			t.Fatalf("second delete: %v", err)
		}
		if _, err := s.GetTOTP(ctx, "alice"); !errors.Is(err, mfa.ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
	})

	t.Run("advance only forward", func(t *testing.T) {
		s := newStore(t)
		_ = s.PutTOTP(ctx, factor("alice"))
		for _, tt := range []struct {
			step int64
			want bool
		}{{100, false}, {99, false}, {101, true}, {101, false}, {103, true}} {
			if got, err := s.AdvanceTOTP(ctx, "alice", tt.step); err != nil || got != tt.want {
				t.Fatalf("AdvanceTOTP(%d) = %v, %v", tt.step, got, err)
			}
		}
		if got, _ := s.GetTOTP(ctx, "alice"); got.LastStep != 103 {
			t.Fatalf("LastStep = %d", got.LastStep)
		}
		if ok, err := s.AdvanceTOTP(ctx, "nobody", 1); ok || err != nil {
			t.Fatalf("unknown subject = %v, %v", ok, err)
		}
	})

	t.Run("concurrent advance has one winner", func(t *testing.T) {
		s := newStore(t)
		_ = s.PutTOTP(ctx, factor("alice"))
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, _ := s.AdvanceTOTP(ctx, "alice", 200); ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d advances won", wins)
		}
	})

	t.Run("recovery codes are single-use", func(t *testing.T) {
		s := newStore(t)
		_ = s.PutTOTP(ctx, factor("alice"))
		_ = s.PutTOTP(ctx, factor("bob"))
		if ok, err := s.UseRecoveryCode(ctx, "alice", h("aaaaa-aaaaa")); !ok || err != nil {
			t.Fatalf("first use = %v, %v", ok, err)
		}
		if ok, _ := s.UseRecoveryCode(ctx, "alice", h("aaaaa-aaaaa")); ok {
			t.Fatal("second use accepted")
		}
		if ok, _ := s.UseRecoveryCode(ctx, "alice", h("ccccc-ccccc")); ok {
			t.Fatal("unknown code accepted")
		}
		if ok, _ := s.UseRecoveryCode(ctx, "nobody", h("bbbbb-bbbbb")); ok {
			t.Fatal("code accepted for an unknown subject")
		}
		got, _ := s.GetTOTP(ctx, "alice")
		if len(got.RecoveryCodes) != 1 || !bytes.Equal(got.RecoveryCodes[0], h("bbbbb-bbbbb")) {
			t.Fatalf("remaining = %x", got.RecoveryCodes)
		}
		if bob, _ := s.GetTOTP(ctx, "bob"); len(bob.RecoveryCodes) != 2 {
			t.Fatal("another subject's codes changed")
		}

		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 10 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, _ := s.UseRecoveryCode(ctx, "bob", h("bbbbb-bbbbb")); ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d concurrent uses won", wins)
		}
	})
}

// Passkeys runs the passkey.Store conformance tests.
func Passkeys(t *testing.T, newStore func(t *testing.T) passkey.Store) {
	cred := func(id, subject string, created time.Time) *passkey.Credential {
		return &passkey.Credential{
			ID: []byte(id), SubjectID: subject, Name: "laptop", PublicKey: []byte("cose-key-" + id),
			AttestationType: "none", AttestationFormat: "none", AAGUID: make([]byte, 16),
			Transports: []string{"internal", "hybrid"}, SignCount: 7,
			UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true, CreatedAt: created,
		}
	}

	t.Run("create, get, list", func(t *testing.T) {
		s := newStore(t)
		if err := s.Create(ctx, cred("c1", "alice", base)); err != nil {
			t.Fatal(err)
		}
		if err := s.Create(ctx, cred("c1", "bob", base)); !errors.Is(err, passkey.ErrConflict) {
			t.Fatalf("duplicate ID: %v", err)
		}
		_ = s.Create(ctx, cred("c2", "alice", base.Add(time.Minute)))
		_ = s.Create(ctx, cred("c3", "bob", base))

		got, err := s.Get(ctx, []byte("c1"))
		if err != nil || got.SubjectID != "alice" || string(got.PublicKey) != "cose-key-c1" || got.SignCount != 7 ||
			!slices.Equal(got.Transports, []string{"internal", "hybrid"}) || !got.UserVerified || !got.BackupEligible ||
			!got.BackupState || got.Name != "laptop" || len(got.AAGUID) != 16 || !sameTime(got.CreatedAt, base) || !got.LastUsedAt.IsZero() {
			t.Fatalf("get = %+v, %v", got, err)
		}
		if _, err := s.Get(ctx, []byte("missing")); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
		list, err := s.ListBySubject(ctx, "alice")
		if err != nil || len(list) != 2 || string(list[0].ID) != "c1" || string(list[1].ID) != "c2" {
			t.Fatalf("list = %v, %v", list, err)
		}
		if none, err := s.ListBySubject(ctx, "nobody"); err != nil || len(none) != 0 {
			t.Fatalf("list for nobody = %v, %v", none, err)
		}
	})

	t.Run("touch", func(t *testing.T) {
		s := newStore(t)
		_ = s.Create(ctx, cred("c1", "alice", base))
		if err := s.Touch(ctx, []byte("c1"), 9, false, base.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Get(ctx, []byte("c1"))
		if got.SignCount != 9 || got.BackupState || !sameTime(got.LastUsedAt, base.Add(time.Hour)) {
			t.Fatalf("after touch = %+v", got)
		}
		if err := s.Touch(ctx, []byte("missing"), 1, false, base); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("touch missing: %v", err)
		}
	})

	t.Run("delete only the subject's own", func(t *testing.T) {
		s := newStore(t)
		_ = s.Create(ctx, cred("c1", "alice", base))
		if err := s.Delete(ctx, "bob", []byte("c1")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, []byte("c1")); err != nil {
			t.Fatal("another subject deleted the credential")
		}
		if err := s.Delete(ctx, "alice", []byte("c1")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, []byte("c1")); !errors.Is(err, passkey.ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
		if err := s.Delete(ctx, "alice", []byte("c1")); err != nil {
			t.Fatalf("second delete: %v", err)
		}
	})
}

// UserStore is what Users needs: subjects, identities and credentials.
type UserStore interface {
	iam.UserStore
	password.CredentialStore
}

// UsersOptions adapts the Users suite to stores with stricter rules than
// IAM requires. The zero value is the default suite.
type UsersOptions struct {
	// Roles are granted to the first subject the suite creates, and must be
	// returned by LoadSubject in the same order. Default: editor, reader.
	// Set it for stores that allow one role per subject, or only known roles.
	Roles []string

	// DefaultRoles are granted to the second subject (an empty grant by
	// default). Set it for stores that require at least one role.
	DefaultRoles []string
}

// Users runs the iam.UserStore and password.CredentialStore conformance tests.
func Users(t *testing.T, newStore func(t *testing.T) UserStore) {
	UsersWith(t, newStore, UsersOptions{})
}

// UsersWith runs the Users suite with options.
func UsersWith(t *testing.T, newStore func(t *testing.T) UserStore, opts UsersOptions) {
	roles := opts.Roles
	if len(roles) == 0 {
		roles = []string{"editor", "reader"}
	}
	t.Run("subjects and identities", func(t *testing.T) {
		s := newStore(t)
		g := provider.Identity{Provider: "google", ProviderID: "g-1", Email: "a@example.com"}
		id, err := s.CreateSubject(ctx, g, iam.SignupGrant{Roles: slices.Clone(roles)})
		if err != nil || id == "" {
			t.Fatalf("CreateSubject = %q, %v", id, err)
		}
		// A different identity: IAM never creates two subjects for one
		// identity, and stores may keep emails unique.
		g2 := provider.Identity{Provider: "google", ProviderID: "g-2", Email: "b@example.com"}
		id2, err := s.CreateSubject(ctx, g2, iam.SignupGrant{Roles: slices.Clone(opts.DefaultRoles)})
		if err != nil || id2 == id {
			t.Fatalf("second CreateSubject = %q, %v (first %q)", id2, err, id)
		}

		sub, err := s.LoadSubject(ctx, id)
		if err != nil || sub.ID != id || !slices.Equal(sub.Roles, roles) || sub.Disabled {
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
