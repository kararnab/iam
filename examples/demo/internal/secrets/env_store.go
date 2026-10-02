package secrets

import (
	"context"
	"os"
)

type EnvStore struct{}

func NewEnvStore() *EnvStore {
	return &EnvStore{}
}

func (e *EnvStore) Get(_ context.Context, name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return v, ErrNotFound
	}
	return v, nil
}
