package session

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreGet(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		session *Session
		lookup  string
		wantErr bool
	}{
		{"active", &Session{ID: "a", ExpiresAt: now.Add(time.Hour)}, "a", false},
		{"expired", &Session{ID: "b", ExpiresAt: now.Add(-time.Second)}, "b", true},
		{"missing", &Session{ID: "c", ExpiresAt: now.Add(time.Hour)}, "zzz", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewMemoryStore()
			if err := s.Save(context.Background(), tt.session); err != nil {
				t.Fatal(err)
			}
			_, err := s.Get(context.Background(), tt.lookup)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Get err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Regression: Get used to delete expired sessions while holding only a read lock.
func TestMemoryStoreConcurrentExpiredGet(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	for _, id := range []string{"x", "y", "z"} {
		if err := s.Save(ctx, &Session{ID: id, ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, id := range []string{"x", "y", "z"} {
				_, _ = s.Get(ctx, id)
			}
		}()
	}
	wg.Wait()
}
