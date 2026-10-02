package memstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kararnab/iam/invite"
	"github.com/kararnab/iam/session"
)

func TestInvites(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	s := NewInvites()
	_, hash := session.NewSecret()
	_, otherHash := session.NewSecret()
	if err := s.Create(ctx, &invite.Invite{ID: "i1", TokenHash: hash, Roles: []string{"editor"}, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		hash    []byte
		at      time.Time
		wantErr error
	}{
		{"unknown", otherHash, now, invite.ErrInvalid},
		{"expired", hash, now.Add(2 * time.Hour), invite.ErrInvalid},
		{"consume", hash, now, nil},
		{"single use", hash, now, invite.ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := s.Consume(ctx, tt.hash, "password:new", tt.at)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err == nil && (inv.UsedBy != "password:new" || inv.Roles[0] != "editor") {
				t.Fatalf("invite = %+v", inv)
			}
		})
	}

	got, err := s.GetByTokenHash(ctx, hash)
	if err != nil || got.UsedAt.IsZero() {
		t.Fatalf("get after consume: %+v %v", got, err)
	}
	_ = s.Delete(ctx, "i1")
	if _, err := s.GetByTokenHash(ctx, hash); !errors.Is(err, invite.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}
