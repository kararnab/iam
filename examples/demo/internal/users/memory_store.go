package users

import (
	"context"
	"errors"
	"sync"

	internalprov "github.com/kararnab/iam/provider/inhouse"
)

type MemoryUserStore struct {
	mu    sync.RWMutex
	users map[string]*internalprov.User
}

func NewMemoryUserStore() *MemoryUserStore {
	return &MemoryUserStore{
		users: make(map[string]*internalprov.User),
	}
}

func (s *MemoryUserStore) GetByUsername(
	ctx context.Context,
	username string,
) (*internalprov.User, error) {

	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	return u, nil
}

func (s *MemoryUserStore) Create(
	ctx context.Context,
	user *internalprov.User,
) error {

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.Email]; exists {
		return errors.New("user already exists")
	}

	s.users[user.Email] = user
	return nil
}
