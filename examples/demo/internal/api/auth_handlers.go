package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/session"
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

	ctx := r.Context()
	params := map[string]string{"username": req.Email, "password": req.Password}

	identity, err := h.Passwords.Register(ctx, params)
	switch {
	case errors.Is(err, iam.ErrConflict):
		http.Error(w, "user already exists", http.StatusConflict)
		return
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case err != nil:
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// TODO(P6): sign-up moves into iam.Service.SignUp (invite-only by default).
	subjectID, err := h.Users.CreateSubject(ctx, *identity, iam.SignupGrant{Roles: []string{RoleReader}})
	if err == nil {
		err = h.Users.LinkIdentity(ctx, subjectID, *identity)
	}
	if err != nil {
		_ = h.Passwords.Unregister(ctx, identity.ProviderID)
		http.Error(w, "server error", http.StatusInternalServerError)
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

func clientInfo(r *http.Request) iam.ClientInfo {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return iam.ClientInfo{IP: host, UserAgent: r.UserAgent()}
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

	res, err := h.IAM.Login(r.Context(), iam.AuthRequest{
		Provider: req.Provider,
		Params:   req.Params,
		Mode:     session.ModeBearer,
		Client:   clientInfo(r),
	})
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, res)
}

type tokenReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req tokenReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "missing refresh_token", http.StatusBadRequest)
		return
	}

	if err := h.IAM.Logout(r.Context(), req.RefreshToken); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "logged_out",
	})
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req tokenReq

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	pair, err := h.IAM.Refresh(r.Context(), req.RefreshToken, clientInfo(r))
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}

	writeJSON(w, http.StatusOK, pair)
}
