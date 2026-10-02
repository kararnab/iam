package api

import (
	"crypto/rand"
	"encoding/json"
	"net/http"

	"github.com/kararnab/iam"
	internalprov "github.com/kararnab/iam/provider/inhouse"
	"golang.org/x/crypto/bcrypt"
)

type registerReq struct {
	Email    string `json:"username"`
	Password string `json:"password"`
}

func (h *Handlers) Register(w http.ResponseWriter, r *http.Request) {
	var req registerReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(req.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	user := &internalprov.User{
		ID:           rand.Text(),
		Email:        req.Email,
		PasswordHash: string(hash),
	}

	if err := h.UserStore.Create(r.Context(), user); err != nil {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"status": "registered",
	})
}

type loginReq struct {
	Provider string            `json:"provider"`
	Params   map[string]string `json:"params"`
}

func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.Provider == "" {
		http.Error(w, "missing provider", http.StatusBadRequest)
		return
	}

	res, err := h.IAM.Authenticate(r.Context(), iam.AuthRequest{
		Provider: req.Provider,
		Params:   req.Params,
	})
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

type logoutReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "missing refresh_token", http.StatusBadRequest)
		return
	}

	if err := h.IAM.Revoke(r.Context(), req.RefreshToken); err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "logged_out",
	})
}

type refreshReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	token, err := h.IAM.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": token,
	})
}
