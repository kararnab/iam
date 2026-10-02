package secrets

import (
	"context"
	"errors"
)

var (
	ErrNotFound = errors.New("secret not found")
)

type Store interface {
	Get(ctx context.Context, name string) (string, error)
}

// BuildSecretStore returns the demo's secret source: the environment.
// Add a Vault or KMS store to the chain in front of it for production.
func BuildSecretStore() Store {
	return NewChain(
		NewEnvStore(),
	)
}
