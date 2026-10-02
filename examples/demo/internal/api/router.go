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

	// Protected: authenticate, then authorize with the RBAC policy.
	authn := AuthMiddleware(auth.IAM)
	can := func(action policy.Action, resourceType string, h http.HandlerFunc) http.Handler {
		return authn(PolicyMiddleware(auth.IAM, action, policy.Resource{Type: resourceType})(h))
	}

	mux.Handle("GET /api/books", can(ActionRead, ResourceBook, books.List))
	mux.Handle("POST /api/books", can(ActionWrite, ResourceBook, books.Create))
	mux.Handle("GET /api/books/{id}", can(ActionRead, ResourceBook, books.Get))
	mux.Handle("PUT /api/books/{id}", can(ActionWrite, ResourceBook, books.Update))
	mux.Handle("DELETE /api/books/{id}", can(ActionWrite, ResourceBook, books.Delete))

	// Admin
	mux.Handle("POST /api/invites", can(ActionCreate, ResourceInvite, auth.CreateInvite))
	mux.Handle("POST /admin/keys/rotate", can(ActionRotate, ResourceSigningKey, keyRotationHandler.Rotate))

	return mux
}
