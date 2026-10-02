package api

import (
	"net/http"

	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/session"
)

// MaxBodyBytes bounds request bodies.
const MaxBodyBytes = 1 << 20

// NewRouter wires the public API. Metrics are served separately (see
// main.go) so they are not exposed on the public listener.
func NewRouter(
	h *Handlers,
	books *BookHandlers,
	keyRotationHandler *KeyRotationHandler,
) http.Handler {
	mux := http.NewServeMux()
	auth := h.Auth

	can := func(action policy.Action, resourceType string, hf http.HandlerFunc) http.Handler {
		return auth.RequirePermission(action, resourceType, func(r *http.Request) policy.Resource {
			return policy.Resource{ID: r.PathValue("id")}
		})(hf)
	}
	authed := func(hf http.HandlerFunc) http.Handler { return auth.RequireAuth(hf) }

	// Bearer-token API (JSON)
	mux.HandleFunc("POST /api/register", h.register(session.ModeBearer))
	mux.HandleFunc("POST /api/login", h.login(session.ModeBearer))
	mux.HandleFunc("POST /api/refresh", h.Refresh)
	mux.HandleFunc("POST /api/logout", h.Logout)

	// Cookie sessions (browsers)
	mux.HandleFunc("POST /api/session/register", h.register(session.ModeCookie))
	mux.HandleFunc("POST /api/session/login", h.login(session.ModeCookie))
	mux.Handle("GET /api/session", authed(h.Session))
	mux.HandleFunc("POST /api/session/logout", h.SessionLogout)

	// Account (either mode)
	mux.Handle("GET /api/me", authed(h.Me))
	mux.Handle("GET /api/sessions", authed(h.ListSessions))
	mux.Handle("DELETE /api/sessions/{id}", authed(h.RevokeSession))
	mux.Handle("POST /api/sessions/revoke-others", authed(h.RevokeOtherSessions))
	mux.Handle("POST /api/identities", authed(h.LinkIdentity))

	// Books
	mux.Handle("GET /api/books", can(ActionRead, ResourceBook, books.List))
	mux.Handle("POST /api/books", can(ActionWrite, ResourceBook, books.Create))
	mux.Handle("GET /api/books/{id}", can(ActionRead, ResourceBook, books.Get))
	mux.Handle("PUT /api/books/{id}", can(ActionWrite, ResourceBook, books.Update))
	mux.Handle("DELETE /api/books/{id}", can(ActionWrite, ResourceBook, books.Delete))

	// Admin
	mux.Handle("POST /api/invites", can(ActionCreate, ResourceInvite, h.CreateInvite))
	mux.Handle("POST /admin/keys/rotate", can(ActionRotate, ResourceSigningKey, keyRotationHandler.Rotate))

	return http.MaxBytesHandler(auth.Protect(mux), MaxBodyBytes)
}
