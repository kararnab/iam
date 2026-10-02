package api

import (
	"net/http"

	"github.com/kararnab/iam/policy"
)

// NewRouter wires the public API. Metrics are served separately (see main.go)
// so they are not exposed on the public listener.
func NewRouter(
	auth *Handlers,
	books *BookHandlers,
	keyRotationHandler *KeyRotationHandler,
) http.Handler {
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("POST /api/register", auth.Register)
	mux.HandleFunc("POST /api/login", auth.Login)
	mux.HandleFunc("POST /api/refresh", auth.Refresh)
	mux.HandleFunc("POST /api/logout", auth.Logout)

	// Protected
	authn := AuthMiddleware(auth.IAM)
	mux.Handle("GET /api/books", authn(http.HandlerFunc(books.List)))
	mux.Handle("POST /api/books", authn(http.HandlerFunc(books.Create)))
	mux.Handle("GET /api/books/{id}", authn(http.HandlerFunc(books.Get)))
	mux.Handle("PUT /api/books/{id}", authn(http.HandlerFunc(books.Update)))
	mux.Handle("DELETE /api/books/{id}", authn(http.HandlerFunc(books.Delete)))

	// Admin
	adminOnly := PolicyMiddleware(
		auth.IAM,
		policy.Action(policy.Admin),
		policy.ResourceContext{Type: policy.Admin},
	)
	mux.Handle("POST /admin/keys/rotate", authn(adminOnly(http.HandlerFunc(keyRotationHandler.Rotate))))

	return mux
}
