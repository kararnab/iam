package books

import "context"

type Store interface {
	List(ctx context.Context) ([]Book, error)
	Get(ctx context.Context, id string) (*Book, error)
	Create(ctx context.Context, book Book) error
	Update(ctx context.Context, book Book) error
	Delete(ctx context.Context, id string) error
}
