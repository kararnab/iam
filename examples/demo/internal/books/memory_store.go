package books

import (
	"context"
	"errors"
	"sync"
)

type MemoryStore struct {
	mu    sync.RWMutex
	books map[string]Book
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		books: map[string]Book{
			"1": {ID: "1", Title: "Clean Architecture", Author: "Robert C. Martin"},
			"2": {ID: "2", Title: "Designing Data-Intensive Applications", Author: "Martin Kleppmann"},
		},
	}
}

func (s *MemoryStore) List(ctx context.Context) ([]Book, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Book, 0, len(s.books))
	for _, b := range s.books {
		out = append(out, b)
	}
	return out, nil
}

func (s *MemoryStore) Get(ctx context.Context, id string) (*Book, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, ok := s.books[id]
	if !ok {
		return nil, errors.New("book not found")
	}
	return &b, nil
}

func (s *MemoryStore) Create(ctx context.Context, book Book) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.books[book.ID]; exists {
		return errors.New("book already exists")
	}
	s.books[book.ID] = book
	return nil
}

func (s *MemoryStore) Update(ctx context.Context, book Book) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.books[book.ID]; !exists {
		return errors.New("book not found")
	}
	s.books[book.ID] = book
	return nil
}

func (s *MemoryStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.books, id)
	return nil
}
