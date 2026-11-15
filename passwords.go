package iam

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/metrics"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

// ErrPasswordsNotConfigured is returned by ChangePassword when no provider
// named Config.Recovery.PasswordProvider (default "password") is
// configured.
var ErrPasswordsNotConfigured = errors.New("iam: no provider can change passwords")

// Passwords changes a signed-in subject's password. The Service returned
// by New implements it, and NewServices returns it typed.
//
// It uses the provider named by Config.Recovery.PasswordProvider (default
// "password"), which must implement provider.PasswordSetter. Unlike
// password reset, it needs no token store.
type Passwords interface {
	// ChangePassword checks the current password and sets a new one.
	//
	// The current password is checked exactly like a login: under the same
	// per-login and per-IP throttles and keys, so a wrong current password
	// counts towards the login limit and the change form cannot be used to
	// guess passwords faster than the sign-in form. A throttled attempt
	// returns *RateLimitError, a wrong password ErrInvalidCredentials.
	//
	// The new password is checked against the provider's policy first, so
	// a rejected new password costs no attempt.
	//
	// On success the subject's other sessions are revoked (the session
	// req.SessionID stays signed in), outstanding password-reset tokens are
	// deleted, and the login's failure count starts over.
	ChangePassword(ctx context.Context, req ChangePasswordRequest) error
}

// ChangePasswordRequest changes the password of the subject that owns
// SessionID.
type ChangePasswordRequest struct {
	// SessionID is the public ID of the caller's current session
	// (SessionInfo.ID, from ValidateSession, VerifyAccessToken or
	// httpauth.SessionFrom). It proves the caller is signed in and names
	// the session to keep.
	SessionID string

	// Login is the subject's password login (for example its email). It
	// must belong to the session's subject; IAM does not look it up,
	// because the UserStore maps logins to subjects but not back.
	Login string

	CurrentPassword string
	NewPassword     string
	Client          ClientInfo
}

var _ Passwords = (*service)(nil)

func (s *service) ChangePassword(ctx context.Context, req ChangePasswordRequest) error {
	prov := s.cfg.Recovery.PasswordProvider
	var subjectID string
	fail := func(reason string, err error) error {
		s.cfg.Metrics.Inc(metrics.PasswordChangeFailure)
		s.audit(ctx, audit.Event{
			Type:      audit.EventPasswordChanged,
			SubjectID: subjectID,
			SessionID: req.SessionID,
			Provider:  prov,
			ClientIP:  req.Client.IP,
			Message:   "password change failed",
			Attrs:     map[string]string{"reason": reason},
		})
		return err
	}

	setter, ok := s.providers[prov].(provider.PasswordSetter)
	if !ok {
		return ErrPasswordsNotConfigured
	}

	sess, err := s.sessions.Get(ctx, req.SessionID)
	if err != nil {
		if errors.Is(err, session.ErrInvalid) {
			return fail("invalid_session", ErrInvalidSession)
		}
		return fail("store_error", sessionError(err))
	}
	subjectID = sess.SubjectID
	if _, err := s.sessionSubject(ctx, sess); err != nil {
		reason := "store_error"
		if errors.Is(err, ErrInvalidSession) {
			reason = "invalid_session"
		}
		return fail(reason, err)
	}

	if err := setter.CheckPassword(req.NewPassword); err != nil {
		return fail("password_policy", err)
	}

	// The login must be the subject's own: otherwise the caller could
	// change (and lock) someone else's password.
	login := normalizeLogin(req.Login)
	switch owner, err := s.cfg.Users.ResolveIdentity(ctx, prov, login); {
	case errors.Is(err, ErrNotFound) || (err == nil && owner != subjectID):
		return fail("login_mismatch", fmt.Errorf("%w: the login does not belong to the session's subject", ErrInvalidCredentials))
	case err != nil:
		return fail("store_error", unavailableErr(err))
	}

	// authenticate applies the login throttles, counts a wrong password on
	// the login and IP keys, and clears the login key on success.
	identity, err := s.authenticate(ctx, AuthRequest{
		Provider: prov,
		Params:   map[string]string{"username": login, "password": req.CurrentPassword},
		Client:   req.Client,
	})
	if err != nil {
		reason := "store_error"
		switch {
		case errors.Is(err, ErrRateLimited):
			reason = "rate_limited"
		case errors.Is(err, ErrInvalidCredentials):
			reason = "invalid_credentials"
		}
		return fail(reason, err)
	}

	if err := setter.SetPassword(ctx, identity.ProviderID, req.NewPassword); err != nil {
		return fail("store_error", fmt.Errorf("iam: set password: %w", err))
	}

	// Whoever else held a session, or a reset link, is signed out. Neither
	// undoes the change.
	revoked, _ := s.sessions.RevokeAll(ctx, subjectID, sess.ID)
	if store := s.cfg.Recovery.Tokens; store != nil {
		_ = store.DeleteBySubject(ctx, subjectID, onetime.PasswordReset)
	}

	s.cfg.Metrics.Inc(metrics.PasswordChanged)
	s.audit(ctx, audit.Event{
		Type:      audit.EventPasswordChanged,
		SubjectID: subjectID,
		SessionID: sess.ID,
		Provider:  prov,
		ClientIP:  req.Client.IP,
		Message:   "password changed",
		Attrs:     map[string]string{"sessions_revoked": strconv.Itoa(revoked)},
	})
	return nil
}
