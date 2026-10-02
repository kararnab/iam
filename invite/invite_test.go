package invite

import (
	"testing"
	"time"
)

func TestUsable(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tests := []struct {
		name string
		inv  Invite
		want bool
	}{
		{"fresh", Invite{ExpiresAt: now.Add(time.Hour)}, true},
		{"at expiry", Invite{ExpiresAt: now}, false},
		{"expired", Invite{ExpiresAt: now.Add(-time.Second)}, false},
		{"used", Invite{ExpiresAt: now.Add(time.Hour), UsedAt: now.Add(-time.Minute)}, false},
	}
	for _, tt := range tests {
		if got := tt.inv.Usable(now); got != tt.want {
			t.Errorf("%s: Usable = %v, want %v", tt.name, got, tt.want)
		}
	}
}
