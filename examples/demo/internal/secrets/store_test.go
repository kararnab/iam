package secrets

import (
	"context"
	"errors"
	"testing"
)

type mapStore map[string]string

func (m mapStore) Get(_ context.Context, k string) (string, error) {
	if v, ok := m[k]; ok {
		return v, nil
	}
	return "", ErrNotFound
}

type failing struct{}

func (failing) Get(context.Context, string) (string, error) { return "", errors.New("vault down") }

func TestChain(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		chain   *ChainStore
		key     string
		want    string
		wantErr error
	}{
		{"first wins", NewChain(mapStore{"a": "1"}, mapStore{"a": "2"}), "a", "1", nil},
		{"falls through", NewChain(mapStore{}, mapStore{"a": "2"}), "a", "2", nil},
		{"missing everywhere", NewChain(mapStore{}, mapStore{}), "a", "", ErrNotFound},
		{"backend error stops the chain", NewChain(failing{}, mapStore{"a": "2"}), "a", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.chain.Get(ctx, tt.key)
			if tt.name == "backend error stops the chain" {
				if err == nil || errors.Is(err, ErrNotFound) {
					t.Fatalf("err = %v, want backend error", err)
				}
				return
			}
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Fatalf("Get = %q, %v; want %q, %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestEnvStore(t *testing.T) {
	t.Setenv("IAM_TEST_SECRET", "v")
	if v, err := NewEnvStore().Get(context.Background(), "IAM_TEST_SECRET"); err != nil || v != "v" {
		t.Fatalf("Get = %q, %v", v, err)
	}
	if _, err := NewEnvStore().Get(context.Background(), "IAM_TEST_UNSET"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unset: %v", err)
	}
}
