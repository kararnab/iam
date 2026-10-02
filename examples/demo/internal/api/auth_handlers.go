package api

import (
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/session"
)

func clientInfo(r *http.Request) iam.ClientInfo {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return iam.ClientInfo{IP: host, UserAgent: r.UserAgent()}
}

// writeAuthError maps IAM errors to HTTP responses without revealing which
// part of a credential was wrong.
func writeAuthError(w http.ResponseWriter, err error, fallback string) {
	var rl *iam.RateLimitError
	switch {
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(rl.RetryAfter.Seconds()))))
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, iam.ErrAlreadyRegistered):
		http.Error(w, "user already exists", http.StatusConflict)
	case errors.Is(err, iam.ErrSignupClosed), errors.Is(err, iam.ErrInvalidInvite):
		http.Error(w, "sign-up not allowed", http.StatusForbidden)
	default:
		http.Error(w, fallback, http.StatusUnauthorized)
	}
}

type registerReq struct {
	Email    string `json:"username"`
	Password string `json:"password"`
	Invite   string `json:"invite"`
}

// Register signs up with a username and password. With the default
// invite-only policy, "invite" must hold a token from POST /api/invites.
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

	res, err := h.IAM.SignUp(r.Context(), iam.SignUpRequest{
		InviteToken: req.Invite,
		Provider:    password.ProviderName,
		Params:      map[string]string{"username": req.Email, "password": req.Password},
		Mode:        session.ModeBearer,
		Client:      clientInfo(r),
	})
	if err != nil {
		writeAuthError(w, err, "sign-up failed")
		return
	}

	writeJSON(w, http.StatusCreated, res)
}

type inviteReq struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// CreateInvite issues an invite. Only admins reach this handler (policy),
// and the roles an invite may grant are restricted here.
func (h *Handlers) CreateInvite(w http.ResponseWriter, r *http.Request) {
	var req inviteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(req.Roles) == 0 {
		req.Roles = []string{RoleReader}
	}
	for _, role := range req.Roles {
		if role != RoleReader && role != RoleEditor {
			http.Error(w, "invites may grant reader or editor only", http.StatusBadRequest)
			return
		}
	}

	subject, _ := SubjectFromContext(r.Context())
	inv, err := h.IAM.CreateInvite(r.Context(), iam.InviteRequest{
		CreatedBy: subject.ID,
		Email:     req.Email,
		Roles:     req.Roles,
		TTL:       72 * time.Hour,
	})
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, inv)
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

	res, err := h.IAM.Login(r.Context(), iam.AuthRequest{
		Provider: req.Provider,
		Params:   req.Params,
		Mode:     session.ModeBearer,
		Client:   clientInfo(r),
	})
	if err != nil {
		writeAuthError(w, err, "invalid credentials")
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
