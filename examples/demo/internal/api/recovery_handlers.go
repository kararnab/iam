package api

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/httpauth"
	"github.com/kararnab/iam/v2/password"
)

// Mail is a link the application would email. Token goes into the link.
type Mail struct {
	Kind  string // "password_reset" or "email_verification"
	To    string
	Token string
}

// Mailer delivers mail. It must not fail the request: a reset response must
// look the same whether or not anything was sent.
type Mailer func(ctx context.Context, m Mail)

type forgotReq struct {
	Username string `json:"username"`
}

// ForgotPassword always answers 202 with the same body, so it does not
// reveal which accounts exist.
func (h *Handlers) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotReq
	if !decode(w, r, &req) {
		return
	}
	issued, err := h.Recovery.StartPasswordReset(r.Context(), iam.PasswordResetRequest{Login: req.Username, Client: h.Auth.ClientInfo(r)})
	var rl *iam.RateLimitError
	switch {
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(rl.RetryAfter.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "too many attempts")
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "try again later")
		return
	}
	if issued != nil {
		// The demo's logins are email addresses. Deliver after responding in
		// a real application, so timing does not reveal the account either.
		h.Mail(context.WithoutCancel(r.Context()), Mail{Kind: "password_reset", To: issued.Login, Token: issued.Token})
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "if the account exists, a reset link has been sent"})
}

type resetReq struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// ResetPassword sets a new password with a reset token. Every session of the
// account is signed out.
func (h *Handlers) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetReq
	if !decode(w, r, &req) {
		return
	}
	_, err := h.Recovery.CompletePasswordReset(r.Context(), iam.CompletePasswordResetRequest{
		Token: req.Token, NewPassword: req.Password, Client: h.Auth.ClientInfo(r),
	})
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, password.ErrTooShort), errors.Is(err, password.ErrTooLong):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, iam.ErrInvalidOneTimeToken):
		writeError(w, http.StatusBadRequest, "invalid or expired token")
	default:
		writeError(w, http.StatusServiceUnavailable, "try again later")
	}
}

type emailReq struct {
	Email string `json:"email"`
}

// StartEmailVerification sends a verification link to an address of the
// signed-in user.
func (h *Handlers) StartEmailVerification(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	var req emailReq
	if !decode(w, r, &req) {
		return
	}
	issued, err := h.Recovery.StartEmailVerification(r.Context(), iam.EmailVerificationRequest{
		SubjectID: subject.ID, Email: req.Email, Client: h.Auth.ClientInfo(r),
	})
	switch {
	case errors.Is(err, iam.ErrInvalidEmail):
		writeError(w, http.StatusBadRequest, "invalid email address")
		return
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "try again later")
		return
	}
	h.Mail(context.WithoutCancel(r.Context()), Mail{Kind: "email_verification", To: issued.Email, Token: issued.Token})
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "verification link sent"})
}

type verifyReq struct {
	Token string `json:"token"`
}

// VerifyEmail uses a verification token. A real application would now
// record the address as verified on its user.
func (h *Handlers) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyReq
	if !decode(w, r, &req) {
		return
	}
	got, err := h.Recovery.CompleteEmailVerification(r.Context(), req.Token, h.Auth.ClientInfo(r))
	switch {
	case errors.Is(err, iam.ErrInvalidOneTimeToken):
		writeError(w, http.StatusBadRequest, "invalid or expired token")
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "try again later")
	default:
		writeJSON(w, http.StatusOK, got)
	}
}
