package api

import (
	"crypto/rand"
	"encoding/json"
	"net/http"

	"github.com/kararnab/iam/examples/demo/internal/books"
)

// BookHandlers exposes CRUD APIs for books.
//
// Responsibilities:
//   - HTTP request/response handling only
//   - Delegates persistence to books.Store
//   - Assumes authentication is already enforced via middleware
//
// Does NOT:
//   - Perform authentication
//   - Perform authorization logic (policy comes later)
//   - Store state internally
type BookHandlers struct {
	Store books.Store
}

// NewBookHandlers creates a new BookHandlers instance.
func NewBookHandlers(store books.Store) *BookHandlers {
	return &BookHandlers{Store: store}
}

// List ================================
// GET /api/books
// ================================
func (h *BookHandlers) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.List(r.Context())
	if err != nil {
		http.Error(w, "failed to list books", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, list)
}

// Get ================================
// GET /api/books/{id}
// ================================
func (h *BookHandlers) Get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	book, err := h.Store.Get(r.Context(), id)
	if err != nil {
		http.Error(w, "book not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, book)
}

// Create ================================
// POST /api/books
// ================================
func (h *BookHandlers) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Title  string `json:"title"`
		Author string `json:"author"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Author == "" {
		http.Error(w, "missing title or author", http.StatusBadRequest)
		return
	}

	book := books.Book{
		ID:     rand.Text(),
		Title:  req.Title,
		Author: req.Author,
	}

	if err := h.Store.Create(r.Context(), book); err != nil {
		http.Error(w, "book already exists", http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusCreated, book)
}

// Update ================================
// PUT /api/books/{id}
// ================================
func (h *BookHandlers) Update(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var req struct {
		Title  string `json:"title"`
		Author string `json:"author"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Title == "" || req.Author == "" {
		http.Error(w, "missing title or author", http.StatusBadRequest)
		return
	}

	book := books.Book{
		ID:     id,
		Title:  req.Title,
		Author: req.Author,
	}

	if err := h.Store.Update(r.Context(), book); err != nil {
		http.Error(w, "book not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, book)
}

// Delete ================================
// DELETE /api/books/{id}
// ================================
func (h *BookHandlers) Delete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	if err := h.Store.Delete(r.Context(), id); err != nil {
		http.Error(w, "book not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
