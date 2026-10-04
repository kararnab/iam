package api

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/httpauth"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/session"
)

// Handlers exposes authentication endpoints in two flavors:
//
//   - /api/login, /api/refresh, /api/logout, /api/register: bearer tokens
//     in JSON, for API and mobile clients;
//   - /api/session/...: an HttpOnly session cookie plus a CSRF token, for
//     same-origin web apps.
type Handlers struct {
	IAM      iam.Service
	MFA      iam.MFA
	Recovery iam.Recovery
	Auth     *httpauth.Middleware
	Mail     Mailer
}

func NewHandlers(svc iam.Service, auth *httpauth.Middleware, mail Mailer) *Handlers {
	rec, _ := svc.(iam.Recovery)
	m, _ := svc.(iam.MFA)
	return &Handlers{IAM: svc, MFA: m, Recovery: rec, Auth: auth, Mail: mail}
}

// writeAuthError maps IAM errors to HTTP responses without revealing which
// part of a credential was wrong.
func writeAuthError(w http.ResponseWriter, err error, fallback string) {
	var rl *iam.RateLimitError
	var needMFA *iam.MFARequiredError
	switch {
	case errors.As(err, &needMFA):
		// The password was right; no session yet. The client sends the
		// challenge back with a code to .../login/mfa.
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "mfa required", "mfa_required": true,
			"challenge": needMFA.Challenge, "expires_at": needMFA.ExpiresAt,
		})
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(rl.RetryAfter.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "too many attempts")
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, iam.ErrAlreadyRegistered):
		writeError(w, http.StatusConflict, "user already exists")
	case errors.Is(err, iam.ErrSignupClosed), errors.Is(err, iam.ErrInvalidInvite):
		writeError(w, http.StatusForbidden, "sign-up not allowed")
	default:
		writeError(w, http.StatusUnauthorized, fallback)
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad request")
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Login and sign-up (both modes)
// ---------------------------------------------------------------------------

type loginReq struct {
	Provider string            `json:"provider"`
	Params   map[string]string `json:"params"`
}

type registerReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Invite   string `json:"invite"`
}

// sessionResponse is the body of cookie-mode endpoints. The session token
// itself is only in the cookie.
type sessionResponse struct {
	Subject   iam.Subject     `json:"subject"`
	Session   iam.SessionInfo `json:"session"`
	CSRFToken string          `json:"csrf_token"`
}

func (h *Handlers) login(mode session.Mode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req loginReq
		if !decode(w, r, &req) {
			return
		}
		if req.Provider == "" {
			writeError(w, http.StatusBadRequest, "missing provider")
			return
		}
		res, err := h.IAM.Login(r.Context(), iam.AuthRequest{
			Provider: req.Provider,
			Params:   req.Params,
			Mode:     mode,
			Client:   h.Auth.ClientInfo(r),
		})
		if err != nil {
			writeAuthError(w, err, "invalid credentials")
			return
		}
		h.respond(w, http.StatusOK, res)
	}
}

func (h *Handlers) register(mode session.Mode) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerReq
		if !decode(w, r, &req) {
			return
		}
		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "missing fields")
			return
		}
		res, err := h.IAM.SignUp(r.Context(), iam.SignUpRequest{
			InviteToken: req.Invite,
			Provider:    password.ProviderName,
			Params:      map[string]string{"username": req.Username, "password": req.Password},
			Mode:        mode,
			Client:      h.Auth.ClientInfo(r),
		})
		if err != nil {
			writeAuthError(w, err, "sign-up failed")
			return
		}
		h.respond(w, http.StatusCreated, res)
	}
}

// respond writes a login result: tokens in JSON for bearer mode, a cookie
// plus subject, session and CSRF token for cookie mode.
func (h *Handlers) respond(w http.ResponseWriter, status int, res *iam.LoginResult) {
	if res.Mode == session.ModeCookie {
		csrf := h.Auth.StartSession(w, res)
		writeJSON(w, status, sessionResponse{Subject: res.Subject, Session: res.Session, CSRFToken: csrf})
		return
	}
	writeJSON(w, status, res)
}

// ---------------------------------------------------------------------------
// Bearer mode
// ---------------------------------------------------------------------------

type tokenReq struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *Handlers) Refresh(w http.ResponseWriter, r *http.Request) {
	var req tokenReq
	if !decode(w, r, &req) {
		return
	}
	pair, err := h.IAM.Refresh(r.Context(), req.RefreshToken, h.Auth.ClientInfo(r))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handlers) Logout(w http.ResponseWriter, r *http.Request) {
	var req tokenReq
	if !decode(w, r, &req) {
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "missing refresh_token")
		return
	}
	if err := h.IAM.Logout(r.Context(), req.RefreshToken); err != nil {
		writeError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// ---------------------------------------------------------------------------
// Cookie mode
// ---------------------------------------------------------------------------

// Session returns the current cookie session and a fresh CSRF token.
func (h *Handlers) Session(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	sess, _ := httpauth.SessionFrom(r.Context())
	writeJSON(w, http.StatusOK, sessionResponse{Subject: *subject, Session: *sess, CSRFToken: h.Auth.CSRFToken(r)})
}

func (h *Handlers) SessionLogout(w http.ResponseWriter, r *http.Request) {
	if err := h.Auth.EndSession(w, r); err != nil {
		writeError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// ---------------------------------------------------------------------------
// Both modes
// ---------------------------------------------------------------------------

func (h *Handlers) Me(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	writeJSON(w, http.StatusOK, subject)
}

func (h *Handlers) ListSessions(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	list, err := h.IAM.ListSessions(r.Context(), subject.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server error")
		return
	}
	current, _ := httpauth.SessionFrom(r.Context())
	type item struct {
		iam.SessionInfo
		Current bool `json:"current"`
	}
	out := make([]item, 0, len(list))
	for _, s := range list {
		out = append(out, item{SessionInfo: s, Current: current != nil && current.ID == s.ID})
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handlers) RevokeSession(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	err := h.IAM.RevokeSession(r.Context(), subject.ID, r.PathValue("id"))
	switch {
	case errors.Is(err, iam.ErrNotFound):
		writeError(w, http.StatusNotFound, "session not found")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "server error")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// RevokeOtherSessions is "log out everywhere else": every session of the
// caller except the current one ends.
func (h *Handlers) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	current, _ := httpauth.SessionFrom(r.Context())
	keep := ""
	if current != nil {
		keep = current.ID
	}
	n, err := h.IAM.RevokeAllSessions(r.Context(), subject.ID, keep)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"revoked": n})
}

// LinkIdentity links another provider identity (for example Google) to the
// caller's account.
func (h *Handlers) LinkIdentity(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	subject, _ := httpauth.SubjectFrom(r.Context())
	err := h.IAM.LinkIdentity(r.Context(), subject.ID, iam.AuthRequest{
		Provider: req.Provider, Params: req.Params, Client: h.Auth.ClientInfo(r),
	})
	switch {
	case errors.Is(err, iam.ErrIdentityLinked):
		writeError(w, http.StatusConflict, "identity belongs to another account")
	case err != nil:
		writeAuthError(w, err, "invalid credentials")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

type inviteReq struct {
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// CreateInvite issues an invite. The policy decides who reaches this
// handler; the roles an invite may grant are restricted here.
func (h *Handlers) CreateInvite(w http.ResponseWriter, r *http.Request) {
	var req inviteReq
	if !decode(w, r, &req) {
		return
	}
	if len(req.Roles) == 0 {
		req.Roles = []string{RoleReader}
	}
	for _, role := range req.Roles {
		if role != RoleReader && role != RoleEditor {
			writeError(w, http.StatusBadRequest, "invites may grant reader or editor only")
			return
		}
	}
	subject, _ := httpauth.SubjectFrom(r.Context())
	inv, err := h.IAM.CreateInvite(r.Context(), iam.InviteRequest{
		CreatedBy: subject.ID,
		Email:     req.Email,
		Roles:     req.Roles,
		TTL:       72 * time.Hour,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server error")
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}
