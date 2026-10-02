package secrets

import (
	"context"
	"errors"
)

type ChainStore struct {
	stores []Store
}

func NewChain(stores ...Store) *ChainStore {
	return &ChainStore{stores: stores}
}

func (c *ChainStore) Get(ctx context.Context, name string) (string, error) {
	for _, store := range c.stores {
		b, err := store.Get(ctx, name)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return b, err
		}
	}
	return "", ErrNotFound
}
