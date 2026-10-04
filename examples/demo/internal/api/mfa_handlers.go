package api

import (
	"errors"
	"net/http"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/httpauth"
)

type mfaLoginReq struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

// loginMFA completes a login that answered 401 mfa_required. The session
// mode comes from the challenge, so the route only picks the response form.
func (h *Handlers) loginMFA(w http.ResponseWriter, r *http.Request) {
	var req mfaLoginReq
	if !decode(w, r, &req) {
		return
	}
	res, err := h.MFA.CompleteMFA(r.Context(), iam.MFARequest{Challenge: req.Challenge, Code: req.Code, Client: h.Auth.ClientInfo(r)})
	if err != nil {
		writeMFAError(w, err)
		return
	}
	h.respond(w, http.StatusOK, res)
}

func writeMFAError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, iam.ErrInvalidMFACode):
		writeError(w, http.StatusUnauthorized, "invalid code")
	case errors.Is(err, iam.ErrMFAAlreadyEnrolled):
		writeError(w, http.StatusConflict, "already enrolled")
	case errors.Is(err, iam.ErrMFANotEnrolled):
		writeError(w, http.StatusConflict, "not enrolled")
	case errors.Is(err, iam.ErrMFANotConfigured):
		writeError(w, http.StatusNotFound, "mfa is not enabled")
	default:
		writeAuthError(w, err, "invalid code")
	}
}

// BeginTOTP returns a new secret for the signed-in user to add to an app.
func (h *Handlers) BeginTOTP(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	e, err := h.MFA.BeginTOTPEnrollment(r.Context(), subject.ID, subject.ID)
	if err != nil {
		writeMFAError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"secret": e.Secret, "uri": e.URI})
}

type codeReq struct {
	Code string `json:"code"`
}

// ConfirmTOTP turns TOTP on with a first code and returns recovery codes.
func (h *Handlers) ConfirmTOTP(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	var req codeReq
	if !decode(w, r, &req) {
		return
	}
	codes, err := h.MFA.ConfirmTOTPEnrollment(r.Context(), subject.ID, req.Code)
	if err != nil {
		writeMFAError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"recovery_codes": codes})
}

// DisableTOTP turns TOTP off after a fresh code (step-up).
func (h *Handlers) DisableTOTP(w http.ResponseWriter, r *http.Request) {
	subject, _ := httpauth.SubjectFrom(r.Context())
	var req codeReq
	if !decode(w, r, &req) {
		return
	}
	if err := h.MFA.VerifyMFA(r.Context(), subject.ID, req.Code, h.Auth.ClientInfo(r)); err != nil {
		writeMFAError(w, err)
		return
	}
	if err := h.MFA.DisableTOTP(r.Context(), subject.ID); err != nil {
		writeMFAError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
