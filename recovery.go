package iam

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/metrics"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
)

var (
	// ErrRecoveryNotConfigured is returned by Recovery methods when
	// Config.Recovery.Tokens is not set, or (for password reset) when no
	// provider can set passwords.
	ErrRecoveryNotConfigured = errors.New("iam: password reset and email verification are not configured")

	// ErrInvalidOneTimeToken is returned for unknown, used or expired
	// password-reset and email-verification tokens, and for a token used
	// for the wrong purpose or whose subject is gone.
	ErrInvalidOneTimeToken = onetime.ErrInvalid

	// ErrInvalidEmail is returned by StartEmailVerification for an address
	// that cannot be one.
	ErrInvalidEmail = errors.New("iam: invalid email address")
)

// Recovery is password reset and email verification. The Service returned
// by New implements it:
//
//	rec := svc.(iam.Recovery)
//
// It is a separate interface so that adding it did not change Service.
// IAM sends no email: the Start methods return a token for the
// application to deliver, typically as a link.
type Recovery interface {
	// StartPasswordReset issues a single-use, expiring token that lets the
	// holder set a new password for req.Login, and invalidates earlier
	// reset tokens of that subject.
	//
	// When no active subject has this login it returns (nil, nil). Answer
	// the client the same way in both cases ("if the account exists, we
	// sent a link"), and deliver the token outside the request, so that the
	// response does not reveal which logins exist. Requests are throttled
	// per login and per IP like failed logins (*RateLimitError).
	StartPasswordReset(ctx context.Context, req PasswordResetRequest) (*IssuedToken, error)

	// CompletePasswordReset sets a new password with a reset token and
	// signs the subject out everywhere. The token is only used up once the
	// new password passes the provider's policy, so a rejected password can
	// be corrected. It returns the subject's ID.
	CompletePasswordReset(ctx context.Context, req CompletePasswordResetRequest) (subjectID string, err error)

	// StartEmailVerification issues a single-use, expiring token proving
	// that the holder receives mail at req.Email, and invalidates the
	// subject's earlier verification tokens. The application authorizes the
	// request (normally: the subject itself, signed in).
	StartEmailVerification(ctx context.Context, req EmailVerificationRequest) (*IssuedToken, error)

	// CompleteEmailVerification uses up a verification token and returns
	// the verified address. IAM does not store it: the application records
	// that the subject's email is verified.
	CompleteEmailVerification(ctx context.Context, token string, client ClientInfo) (*VerifiedEmail, error)
}

// PasswordResetRequest asks for a password-reset token.
type PasswordResetRequest struct {
	Login  string // the password login (for example an email address)
	Client ClientInfo
}

// CompletePasswordResetRequest sets a new password with a reset token.
type CompletePasswordResetRequest struct {
	Token       string
	NewPassword string
	Client      ClientInfo
}

// EmailVerificationRequest asks for an email-verification token.
type EmailVerificationRequest struct {
	SubjectID string
	Email     string
	Client    ClientInfo
}

// IssuedToken is returned once by the Start methods. Token is the only
// copy of the secret: deliver it to the address it belongs to, never to the
// requester. It has no JSON encoding on purpose.
type IssuedToken struct {
	ID        string    `json:"-"`
	Token     string    `json:"-"`
	SubjectID string    `json:"-"`
	Login     string    `json:"-"` // password reset: the normalized login
	Email     string    `json:"-"` // email verification: the normalized address
	ExpiresAt time.Time `json:"-"`
}

// VerifiedEmail is returned by CompleteEmailVerification.
type VerifiedEmail struct {
	SubjectID string `json:"subject_id"`
	Email     string `json:"email"`
}

var _ Recovery = (*service)(nil)

func normalizeLogin(login string) string { return strings.ToLower(strings.TrimSpace(login)) }

// passwordSetter returns the provider that resets passwords, if any.
func (s *service) passwordSetter() provider.PasswordSetter {
	if s.cfg.Recovery.Tokens == nil {
		return nil
	}
	setter, _ := s.providers[s.cfg.Recovery.PasswordProvider].(provider.PasswordSetter)
	return setter
}

// issue stores a new token of one purpose, replacing the subject's
// earlier ones.
func (s *service) issue(ctx context.Context, t onetime.Token, ttl time.Duration) (*IssuedToken, error) {
	store := s.cfg.Recovery.Tokens
	if err := store.DeleteBySubject(ctx, t.SubjectID, t.Purpose); err != nil {
		return nil, unavailableErr(err)
	}
	now := s.cfg.Now()
	secret, hash := session.NewSecret()
	t.ID, t.TokenHash, t.CreatedAt, t.ExpiresAt = rand.Text(), hash, now, now.Add(ttl)
	if err := store.Create(ctx, &t); err != nil {
		return nil, unavailableErr(err)
	}
	return &IssuedToken{ID: t.ID, Token: secret, SubjectID: t.SubjectID, Login: t.Login, Email: t.Email, ExpiresAt: t.ExpiresAt}, nil
}

// ---------------------------------------------------------------------------
// Password reset
// ---------------------------------------------------------------------------

func (s *service) StartPasswordReset(ctx context.Context, req PasswordResetRequest) (*IssuedToken, error) {
	prov := s.cfg.Recovery.PasswordProvider
	report := func(subjectID, reason string) {
		e := audit.Event{
			Type:      audit.EventPasswordResetRequested,
			SubjectID: subjectID,
			Provider:  prov,
			ClientIP:  req.Client.IP,
			Message:   "password reset requested",
		}
		if reason != "" {
			e.Message = "password reset not issued"
			e.Attrs = map[string]string{"reason": reason}
		}
		s.audit(ctx, e)
	}

	if s.passwordSetter() == nil {
		return nil, ErrRecoveryNotConfigured
	}
	login := normalizeLogin(req.Login)
	if login == "" {
		report("", "unknown_login")
		return nil, nil
	}
	if err := s.throttleReset(ctx, login, req.Client); err != nil {
		report("", "rate_limited")
		return nil, err
	}

	subjectID, err := s.cfg.Users.ResolveIdentity(ctx, prov, login)
	if errors.Is(err, ErrNotFound) {
		report("", "unknown_login")
		return nil, nil
	}
	if err != nil {
		report("", "store_error")
		return nil, unavailableErr(err)
	}
	if _, err := s.loadActiveSubject(ctx, subjectID); err != nil {
		if subjectGone(err) {
			report(subjectID, reasonFor(err))
			return nil, nil
		}
		report(subjectID, "store_error")
		return nil, unavailableErr(err)
	}

	issued, err := s.issue(ctx, onetime.Token{Purpose: onetime.PasswordReset, SubjectID: subjectID, Login: login}, s.cfg.Recovery.ResetTTL)
	if err != nil {
		report(subjectID, "store_error")
		return nil, err
	}
	s.cfg.Metrics.Inc(metrics.PasswordResetRequested)
	report(subjectID, "")
	return issued, nil
}

// throttleReset counts every reset request, per login and per IP, with the
// login limiters. The keys differ from the login keys, so reset requests
// never lock anyone out of signing in.
func (s *service) throttleReset(ctx context.Context, login string, client ClientInfo) error {
	var keys []limitKey
	if l := s.cfg.RateLimit.PerLogin; l != nil {
		keys = append(keys, limitKey{l, "reset_login", "reset:login:" + login})
	}
	if l := s.cfg.RateLimit.PerIP; l != nil && client.IP != "" {
		keys = append(keys, limitKey{l, "reset_ip", "reset:ip:" + client.IP})
	}
	for _, k := range keys {
		r, err := k.limiter.Check(ctx, k.key)
		if err != nil {
			return unavailableErr(err)
		}
		if !r.Allowed {
			s.cfg.Metrics.Inc(metrics.RateLimited)
			s.audit(ctx, audit.Event{
				Type:     audit.EventRateLimited,
				Provider: s.cfg.Recovery.PasswordProvider,
				ClientIP: client.IP,
				Message:  "attempt throttled",
				Attrs:    map[string]string{"scope": k.scope},
			})
			return &RateLimitError{RetryAfter: r.RetryAfter}
		}
	}
	for _, k := range keys {
		_, _ = k.limiter.Fail(ctx, k.key)
	}
	return nil
}

func (s *service) CompletePasswordReset(ctx context.Context, req CompletePasswordResetRequest) (string, error) {
	prov := s.cfg.Recovery.PasswordProvider
	var subjectID string
	fail := func(reason string, err error) (string, error) {
		s.cfg.Metrics.Inc(metrics.PasswordResetFailure)
		s.audit(ctx, audit.Event{
			Type:      audit.EventPasswordReset,
			SubjectID: subjectID,
			Provider:  prov,
			ClientIP:  req.Client.IP,
			Message:   "password reset failed",
			Attrs:     map[string]string{"reason": reason},
		})
		return "", err
	}

	setter := s.passwordSetter()
	if setter == nil {
		return "", ErrRecoveryNotConfigured
	}
	store := s.cfg.Recovery.Tokens
	hash, err := session.HashSecret(req.Token)
	if err != nil {
		return fail("invalid_token", ErrInvalidOneTimeToken)
	}
	t, err := store.GetByTokenHash(ctx, hash)
	switch {
	case errors.Is(err, onetime.ErrNotFound):
		return fail("invalid_token", ErrInvalidOneTimeToken)
	case err != nil:
		return fail("store_error", unavailableErr(err))
	case t.Purpose != onetime.PasswordReset || !t.Usable(s.cfg.Now()):
		return fail("invalid_token", ErrInvalidOneTimeToken)
	}
	subjectID = t.SubjectID

	// Reject a bad password before using up the token, so it can be fixed.
	if err := setter.CheckPassword(req.NewPassword); err != nil {
		return fail("password_policy", err)
	}
	// The login must still belong to the subject, and the subject be active.
	switch owner, err := s.cfg.Users.ResolveIdentity(ctx, prov, t.Login); {
	case errors.Is(err, ErrNotFound) || (err == nil && owner != t.SubjectID):
		return fail("login_changed", ErrInvalidOneTimeToken)
	case err != nil:
		return fail("store_error", unavailableErr(err))
	}
	if _, err := s.loadActiveSubject(ctx, t.SubjectID); err != nil {
		if subjectGone(err) {
			return fail(reasonFor(err), ErrInvalidOneTimeToken)
		}
		return fail("store_error", unavailableErr(err))
	}

	// Consume atomically: of two completions racing on one token, only one
	// sets a password.
	if _, err := store.Consume(ctx, hash, onetime.PasswordReset, s.cfg.Now()); err != nil {
		if errors.Is(err, onetime.ErrInvalid) {
			return fail("invalid_token", ErrInvalidOneTimeToken)
		}
		return fail("store_error", unavailableErr(err))
	}
	if err := setter.SetPassword(ctx, t.Login, req.NewPassword); err != nil {
		return fail("store_error", fmt.Errorf("iam: set password: %w", err))
	}

	// Whoever held a session (or the old password) is signed out, and the
	// login's failure count starts over. Neither undoes the reset.
	revoked, _ := s.sessions.RevokeAll(ctx, t.SubjectID, "")
	_ = store.DeleteBySubject(ctx, t.SubjectID, onetime.PasswordReset)
	if l := s.cfg.RateLimit.PerLogin; l != nil {
		_ = l.Reset(ctx, "login:"+prov+":"+t.Login)
	}

	s.cfg.Metrics.Inc(metrics.PasswordReset)
	s.audit(ctx, audit.Event{
		Type:      audit.EventPasswordReset,
		SubjectID: t.SubjectID,
		Provider:  prov,
		ClientIP:  req.Client.IP,
		Message:   "password reset",
		Attrs:     map[string]string{"token_id": t.ID, "sessions_revoked": fmt.Sprint(revoked)},
	})
	return t.SubjectID, nil
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

func (s *service) StartEmailVerification(ctx context.Context, req EmailVerificationRequest) (*IssuedToken, error) {
	if s.cfg.Recovery.Tokens == nil {
		return nil, ErrRecoveryNotConfigured
	}
	email := normalizeLogin(req.Email)
	if !plausibleEmail(email) {
		return nil, ErrInvalidEmail
	}
	if _, err := s.loadActiveSubject(ctx, req.SubjectID); err != nil {
		if subjectGone(err) {
			return nil, err
		}
		return nil, unavailableErr(err)
	}
	issued, err := s.issue(ctx, onetime.Token{Purpose: onetime.EmailVerification, SubjectID: req.SubjectID, Email: email}, s.cfg.Recovery.VerificationTTL)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{
		Type:      audit.EventEmailVerificationRequested,
		SubjectID: req.SubjectID,
		ClientIP:  req.Client.IP,
		Message:   "email verification requested",
		Attrs:     map[string]string{"token_id": issued.ID},
	})
	return issued, nil
}

func (s *service) CompleteEmailVerification(ctx context.Context, tok string, client ClientInfo) (*VerifiedEmail, error) {
	var subjectID string
	fail := func(reason string, err error) (*VerifiedEmail, error) {
		s.cfg.Metrics.Inc(metrics.EmailVerificationFailure)
		s.audit(ctx, audit.Event{
			Type:      audit.EventEmailVerified,
			SubjectID: subjectID,
			ClientIP:  client.IP,
			Message:   "email verification failed",
			Attrs:     map[string]string{"reason": reason},
		})
		return nil, err
	}

	store := s.cfg.Recovery.Tokens
	if store == nil {
		return nil, ErrRecoveryNotConfigured
	}
	hash, err := session.HashSecret(tok)
	if err != nil {
		return fail("invalid_token", ErrInvalidOneTimeToken)
	}
	t, err := store.Consume(ctx, hash, onetime.EmailVerification, s.cfg.Now())
	if err != nil {
		if errors.Is(err, onetime.ErrInvalid) {
			return fail("invalid_token", ErrInvalidOneTimeToken)
		}
		return fail("store_error", unavailableErr(err))
	}
	subjectID = t.SubjectID
	if _, err := s.loadActiveSubject(ctx, t.SubjectID); err != nil {
		if subjectGone(err) {
			return fail(reasonFor(err), ErrInvalidOneTimeToken)
		}
		return fail("store_error", unavailableErr(err))
	}

	s.cfg.Metrics.Inc(metrics.EmailVerified)
	s.audit(ctx, audit.Event{
		Type:      audit.EventEmailVerified,
		SubjectID: t.SubjectID,
		ClientIP:  client.IP,
		Message:   "email verified",
		Attrs:     map[string]string{"token_id": t.ID},
	})
	return &VerifiedEmail{SubjectID: t.SubjectID, Email: t.Email}, nil
}

// plausibleEmail is a sanity check, not validation: delivery proves the
// address.
func plausibleEmail(email string) bool {
	local, domain, ok := strings.Cut(email, "@")
	return ok && local != "" && domain != "" && len(email) <= 254 &&
		!strings.ContainsAny(email, " \t\r\n<>,;") && !strings.Contains(domain, "@")
}

// unavailableErr wraps a store failure in ErrUnavailable.
func unavailableErr(err error) error {
	if errors.Is(err, ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}
