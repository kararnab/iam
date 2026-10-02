package keys

import "testing"

func TestMemoryProvider(t *testing.T) {
	k := func(id string) Key { return Key{ID: id, Alg: HS256} }

	tests := []struct {
		name      string
		rotate    []string
		prune     int // -1 = no prune
		wantErr   bool
		wantIDs   []string
		wantFound string
	}{
		{"initial", nil, -1, false, []string{"a"}, "a"},
		{"rotate keeps old", []string{"b"}, -1, false, []string{"b", "a"}, "a"},
		{"prune to one old", []string{"b", "c"}, 1, false, []string{"c", "b"}, "b"},
		{"prune all old", []string{"b"}, 0, false, []string{"b"}, "b"},
		{"duplicate of active", []string{"a"}, -1, true, []string{"a"}, "a"},
		{"duplicate of old", []string{"b", "a"}, -1, true, []string{"b", "a"}, "a"},
		{"empty id", []string{""}, -1, true, []string{"a"}, "a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewMemoryProvider(k("a"))
			var err error
			for _, id := range tt.rotate {
				if e := p.Rotate(k(id)); e != nil {
					err = e
				}
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("Rotate err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.prune >= 0 {
				p.Prune(tt.prune)
			}
			got := p.VerificationKeys()
			if len(got) != len(tt.wantIDs) {
				t.Fatalf("keys = %v, want %v", got, tt.wantIDs)
			}
			for i, id := range tt.wantIDs {
				if got[i].ID != id {
					t.Fatalf("keys[%d] = %q, want %q", i, got[i].ID, id)
				}
			}
			if p.ActiveKey().ID != tt.wantIDs[0] {
				t.Fatalf("active = %q", p.ActiveKey().ID)
			}
			if _, ok := Find(p, tt.wantFound); !ok {
				t.Fatalf("Find(%q) failed", tt.wantFound)
			}
			if _, ok := Find(p, "missing"); ok {
				t.Fatal("Find found a missing key")
			}
		})
	}
}
