package books

import (
	"context"
	"testing"
)

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	tests := []struct {
		name    string
		op      func() error
		wantErr bool
	}{
		{"get seeded", func() error { _, err := s.Get(ctx, "1"); return err }, false},
		{"get missing", func() error { _, err := s.Get(ctx, "x"); return err }, true},
		{"create", func() error { return s.Create(ctx, Book{ID: "3", Title: "T", Author: "A"}) }, false},
		{"create duplicate", func() error { return s.Create(ctx, Book{ID: "3"}) }, true},
		{"update", func() error { return s.Update(ctx, Book{ID: "3", Title: "T2", Author: "A"}) }, false},
		{"update missing", func() error { return s.Update(ctx, Book{ID: "x"}) }, true},
		{"delete", func() error { return s.Delete(ctx, "3") }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.op(); (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	if list, _ := s.List(ctx); len(list) != 2 {
		t.Fatalf("list = %d books", len(list))
	}
}
