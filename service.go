package iam

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/metrics"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/ratelimit"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/token"
)

// service is the default, in-process Service.
//
// It orchestrates providers, sessions, tokens, policy and audit, and
// contains no business logic, provider-specific code or HTTP.
type service struct {
	cfg       Config
	providers map[string]provider.AuthProvider
	sessions  *session.Manager
}

// New returns the default Service.
func New(cfg Config) (Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	sessions, err := session.NewManager(cfg.Sessions, cfg.Session)
	if err != nil {
		return nil, err
	}
	providers := make(map[string]provider.AuthProvider, len(cfg.Providers))
	for _, p := range cfg.Providers {
		providers[p.Name()] = p
	}
	return &service{cfg: cfg, providers: providers, sessions: sessions}, nil
}

func (s *service) audit(ctx context.Context, e audit.Event) {
	e.Time = s.cfg.Now()
	_ = s.cfg.Audit.Log(ctx, e)
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

func (s *service) Login(ctx context.Context, req AuthRequest) (*LoginResult, error) {
	fail := func(subjectID, reason string, err error) (*LoginResult, error) {
		s.cfg.Metrics.Inc(metrics.LoginFailure)
		s.audit(ctx, audit.Event{
			Type:      audit.EventLoginFailure,
			SubjectID: subjectID,
			Provider:  req.Provider,
			ClientIP:  req.Client.IP,
			Message:   "login failed",
			Attrs:     map[string]string{"reason": reason},
		})
		return nil, err
	}

	mode := req.Mode
	if mode == "" {
		mode = s.cfg.AllowedModes[0]
	}
	if !s.modeAllowed(mode) {
		return fail("", "mode_not_allowed", ErrModeNotAllowed)
	}

	identity, err := s.authenticate(ctx, req)
	if err != nil {
		reason := "invalid_credentials"
		switch {
		case errors.Is(err, ErrUnknownProvider):
			reason = "unknown_provider"
		case errors.Is(err, ErrRateLimited):
			reason = "rate_limited"
		}
		return fail("", reason, err)
	}

	subjectID, err := s.cfg.Users.ResolveIdentity(ctx, identity.Provider, identity.ProviderID)
	if errors.Is(err, ErrNotFound) {
		err = ErrUnknownIdentity
	}
	if err != nil {
		return fail("", reasonFor(err), err)
	}
	subject, err := s.loadActiveSubject(ctx, subjectID)
	if err != nil {
		return fail(subjectID, reasonFor(err), err)
	}

	// With TOTP enrolled, the first factor alone starts no session.
	if err := s.loginChallenge(ctx, subject, mode, identity.Provider); err != nil {
		var challenge *MFARequiredError
		if !errors.As(err, &challenge) {
			return fail(subject.ID, "store_error", err)
		}
		s.cfg.Metrics.Inc(metrics.MFAChallenge)
		s.audit(ctx, audit.Event{
			Type:      audit.EventMFAChallenge,
			SubjectID: subject.ID,
			Provider:  identity.Provider,
			ClientIP:  req.Client.IP,
			Message:   "first factor accepted; second factor required",
			Attrs:     map[string]string{"mode": string(mode)},
		})
		return nil, err
	}

	res, err := s.startSession(ctx, subject, mode, identity.Provider, req.Client, "")
	if err != nil {
		return fail(subject.ID, "session_error", err)
	}

	s.cfg.Metrics.Inc(metrics.LoginSuccess)
	s.audit(ctx, audit.Event{
		Type:      audit.EventLoginSuccess,
		SubjectID: subject.ID,
		SessionID: res.Session.ID,
		Provider:  identity.Provider,
		ClientIP:  req.Client.IP,
		Message:   "login successful",
		Attrs:     map[string]string{"mode": string(mode)},
	})
	return res, nil
}

func (s *service) modeAllowed(m session.Mode) bool {
	for _, a := range s.cfg.AllowedModes {
		if a == m {
			return true
		}
	}
	return false
}

// startSession creates a session and the credentials for its mode.
// mfaMethod names the second factor used, if any.
func (s *service) startSession(ctx context.Context, subject *Subject, mode session.Mode, providerName string, client ClientInfo, mfaMethod string) (*LoginResult, error) {
	attrs := map[string]string{"provider": providerName}
	if mfaMethod != "" {
		attrs["mfa"] = mfaMethod
	}
	if client.IP != "" {
		attrs["ip"] = client.IP
	}
	if client.UserAgent != "" {
		attrs["user_agent"] = client.UserAgent
	}

	sess, secret, err := s.sessions.Create(ctx, subject.ID, mode, attrs)
	if err != nil {
		return nil, err
	}
	res := &LoginResult{Mode: mode, Subject: *subject, Session: infoFor(sess)}

	switch mode {
	case session.ModeCookie:
		res.SessionToken = secret
	case session.ModeBearer:
		at, err := s.cfg.TokenIssuer.Issue(ctx, claimsFor(subject, sess.ID))
		if err != nil {
			_, _ = s.sessions.Revoke(ctx, secret)
			return nil, err
		}
		res.AccessToken = at
		res.RefreshToken = secret
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Bearer mode
// ---------------------------------------------------------------------------

func (s *service) Refresh(ctx context.Context, refreshToken string, client ClientInfo) (*TokenPair, error) {
	fail := func(sess *session.Session, typ audit.EventType, reason string, err error) (*TokenPair, error) {
		s.cfg.Metrics.Inc(metrics.RefreshFailure)
		e := audit.Event{Type: typ, ClientIP: client.IP, Message: "refresh failed", Attrs: map[string]string{"reason": reason}}
		if sess != nil {
			e.SubjectID, e.SessionID = sess.SubjectID, sess.ID
		}
		if typ == audit.EventRefreshReuse {
			e.Message = "refresh token reuse detected; session revoked"
		}
		s.audit(ctx, e)
		return nil, err
	}

	// Reload the subject before rotating, so roles and attributes are
	// current, a disabled or deleted subject cannot keep refreshing, and a
	// store failure leaves the client's refresh token usable for a retry.
	// Tokens that do not pass Inspect (unknown, expired, or rotated away)
	// go straight to Refresh, which classifies them and detects reuse.
	var subject *Subject
	switch current, err := s.sessions.Inspect(ctx, refreshToken); {
	case err == nil:
		subject, err = s.loadActiveSubject(ctx, current.SubjectID)
		if err != nil {
			if subjectGone(err) {
				_ = s.sessions.RevokeByID(ctx, current.SubjectID, current.ID)
			} else {
				err = fmt.Errorf("%w: %w", ErrUnavailable, err)
			}
			return fail(current, audit.EventRefreshFailure, reasonFor(err), err)
		}
	case !errors.Is(err, session.ErrInvalid):
		return fail(nil, audit.EventRefreshFailure, "store_error", sessionError(err))
	}

	sess, newRefresh, err := s.sessions.Refresh(ctx, refreshToken)
	switch {
	case errors.Is(err, session.ErrReused):
		s.cfg.Metrics.Inc(metrics.RefreshReuse)
		return fail(sess, audit.EventRefreshReuse, "reuse", err)
	case errors.Is(err, session.ErrRaced):
		return fail(sess, audit.EventRefreshFailure, "raced", err)
	case errors.Is(err, session.ErrInvalid):
		return fail(nil, audit.EventRefreshFailure, "invalid_session", err)
	case err != nil:
		return fail(nil, audit.EventRefreshFailure, "store_error", sessionError(err))
	case subject == nil || sess.SubjectID != subject.ID:
		// Unreachable in practice: a token that failed Inspect cannot pass
		// Refresh, and a concurrent rotation between the two calls is
		// reported above as ErrReused or ErrRaced. Defensive only.
		return fail(sess, audit.EventRefreshFailure, "invalid_session", ErrInvalidSession)
	}

	at, err := s.cfg.TokenIssuer.Issue(ctx, claimsFor(subject, sess.ID))
	if err != nil {
		return fail(sess, audit.EventRefreshFailure, "issue_error", err)
	}

	s.cfg.Metrics.Inc(metrics.RefreshSuccess)
	s.audit(ctx, audit.Event{
		Type:      audit.EventRefreshSuccess,
		SubjectID: subject.ID,
		SessionID: sess.ID,
		ClientIP:  client.IP,
		Message:   "token refreshed",
	})
	return &TokenPair{AccessToken: at, RefreshToken: newRefresh}, nil
}

func (s *service) VerifyAccessToken(ctx context.Context, accessToken string) (*Subject, *SessionInfo, error) {
	if s.cfg.TokenVerifier == nil {
		return nil, nil, token.ErrInvalidToken
	}
	claims, err := s.cfg.TokenVerifier.Verify(ctx, accessToken)
	if err != nil {
		s.cfg.Metrics.Inc(metrics.TokenVerifyFailure)
		s.audit(ctx, audit.Event{
			Type:    audit.EventTokenVerifyFailure,
			Message: "access token verification failed",
		})
		return nil, nil, err
	}

	info := &SessionInfo{ID: claims.SessionID, SubjectID: claims.SubjectID, Mode: session.ModeBearer}
	if s.cfg.VerifySessionOnAccess {
		sess, err := s.sessions.Get(ctx, claims.SessionID)
		if err != nil && !errors.Is(err, session.ErrInvalid) {
			return nil, nil, sessionError(err)
		}
		if err != nil || sess.SubjectID != claims.SubjectID || sess.Mode != session.ModeBearer {
			s.cfg.Metrics.Inc(metrics.TokenVerifyFailure)
			return nil, nil, ErrInvalidSession
		}
		*info = infoFor(sess)
	}

	subject := &Subject{ID: claims.SubjectID, Roles: claims.Roles, Attrs: claims.Attrs}
	if s.cfg.LoadSubjectOnAccess {
		subject, err = s.sessionSubject(ctx, &session.Session{ID: claims.SessionID, SubjectID: claims.SubjectID})
		if err != nil {
			if errors.Is(err, ErrInvalidSession) {
				s.cfg.Metrics.Inc(metrics.TokenVerifyFailure)
			}
			return nil, nil, err
		}
	}

	s.cfg.Metrics.Inc(metrics.TokenVerifySuccess)
	return subject, info, nil
}

// ---------------------------------------------------------------------------
// Cookie mode
// ---------------------------------------------------------------------------

func (s *service) ValidateSession(ctx context.Context, sessionToken string) (*Subject, *SessionInfo, error) {
	sess, err := s.sessions.Validate(ctx, sessionToken)
	if err != nil {
		return nil, nil, sessionError(err)
	}
	subject, err := s.sessionSubject(ctx, sess)
	if err != nil {
		return nil, nil, err
	}
	info := infoFor(sess)
	return subject, &info, nil
}

func (s *service) RotateSession(ctx context.Context, sessionToken string) (*LoginResult, error) {
	// Check the subject before rotating: rotating first would discard the
	// client's secret if loading the subject then failed.
	current, err := s.sessions.Validate(ctx, sessionToken)
	if err != nil {
		return nil, sessionError(err)
	}
	subject, err := s.sessionSubject(ctx, current)
	if err != nil {
		return nil, err
	}
	sess, secret, err := s.sessions.Rotate(ctx, sessionToken)
	if err != nil {
		return nil, sessionError(err)
	}
	s.audit(ctx, audit.Event{
		Type:      audit.EventSessionRotated,
		SubjectID: sess.SubjectID,
		SessionID: sess.ID,
		Message:   "session token rotated",
	})
	return &LoginResult{Mode: session.ModeCookie, SessionToken: secret, Subject: *subject, Session: infoFor(sess)}, nil
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

func (s *service) Logout(ctx context.Context, tok string) error {
	sess, err := s.sessions.Revoke(ctx, tok)
	if err != nil {
		return sessionError(err)
	}
	if sess == nil {
		return nil
	}
	s.cfg.Metrics.Inc(metrics.Logout)
	s.audit(ctx, audit.Event{
		Type:      audit.EventLogout,
		SubjectID: sess.SubjectID,
		SessionID: sess.ID,
		Message:   "logged out",
	})
	return nil
}

func (s *service) ListSessions(ctx context.Context, subjectID string) ([]SessionInfo, error) {
	list, err := s.sessions.List(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	out := make([]SessionInfo, 0, len(list))
	for _, sess := range list {
		out = append(out, infoFor(sess))
	}
	return out, nil
}

func (s *service) RevokeSession(ctx context.Context, subjectID, sessionID string) error {
	if err := s.sessions.RevokeByID(ctx, subjectID, sessionID); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	s.cfg.Metrics.Inc(metrics.SessionRevoked)
	s.audit(ctx, audit.Event{
		Type:      audit.EventSessionRevoked,
		SubjectID: subjectID,
		SessionID: sessionID,
		Message:   "session revoked",
	})
	return nil
}

func (s *service) RevokeAllSessions(ctx context.Context, subjectID, exceptSessionID string) (int, error) {
	n, err := s.sessions.RevokeAll(ctx, subjectID, exceptSessionID)
	if err != nil {
		return n, err
	}
	s.audit(ctx, audit.Event{
		Type:      audit.EventSessionsRevokedAll,
		SubjectID: subjectID,
		SessionID: exceptSessionID,
		Message:   "sessions revoked",
		Attrs:     map[string]string{"count": strconv.Itoa(n)},
	})
	return n, nil
}

// ---------------------------------------------------------------------------
// Authorization and identities
// ---------------------------------------------------------------------------

func (s *service) Authorize(
	ctx context.Context,
	subject *Subject,
	action policy.Action,
	resource policy.Resource,
) (*policy.Decision, error) {

	deny := func(subjectID, reason string, err error) (*policy.Decision, error) {
		s.cfg.Metrics.Inc(metrics.PolicyDenied)
		s.audit(ctx, audit.Event{
			Type:      audit.EventPolicyDenied,
			SubjectID: subjectID,
			Message:   "access denied",
			Attrs: map[string]string{
				"action":        string(action),
				"resource_type": resource.Type,
				"resource_id":   resource.ID,
				"reason":        reason,
			},
		})
		return &policy.Decision{Effect: policy.EffectDeny, Reason: reason}, err
	}

	if subject == nil {
		return deny("", "no subject", nil)
	}

	decision, err := s.cfg.Policy.Evaluate(ctx, policy.SubjectContext{
		SubjectID: subject.ID,
		Roles:     subject.Roles,
		Attrs:     subject.Attrs,
	}, action, resource)
	if err != nil {
		return deny(subject.ID, "policy error", err)
	}
	if !decision.Allowed() {
		reason := "no matching policy"
		if decision != nil && decision.Reason != "" {
			reason = decision.Reason
		}
		return deny(subject.ID, reason, nil)
	}
	return decision, nil
}

func (s *service) LinkIdentity(ctx context.Context, subjectID string, req AuthRequest) error {
	if _, err := s.loadActiveSubject(ctx, subjectID); err != nil {
		return err
	}

	identity, err := s.authenticate(ctx, req)
	if err != nil {
		return err
	}

	owner, err := s.cfg.Users.ResolveIdentity(ctx, identity.Provider, identity.ProviderID)
	switch {
	case err == nil && owner == subjectID:
		return nil // already linked to this subject
	case err == nil:
		return ErrIdentityLinked
	case !errors.Is(err, ErrNotFound):
		return err
	}

	if err := s.cfg.Users.LinkIdentity(ctx, subjectID, *identity); err != nil {
		if errors.Is(err, ErrConflict) {
			return ErrIdentityLinked // lost a race with another link
		}
		return err
	}

	s.audit(ctx, audit.Event{
		Type:      audit.EventIdentityLinked,
		SubjectID: subjectID,
		Provider:  identity.Provider,
		ClientIP:  req.Client.IP,
		Message:   "identity linked",
	})
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// authenticate runs a provider behind the failed-login rate limits.
//
// Throttled attempts never reach the provider (no password hashing). Only
// credential failures count; unknown and known logins count the same, so
// throttling reveals nothing about which logins exist.
func (s *service) authenticate(ctx context.Context, req AuthRequest) (*provider.Identity, error) {
	prov, ok := s.providers[req.Provider]
	if !ok {
		return nil, ErrUnknownProvider
	}

	keys := s.limitKeys(req)
	for _, k := range keys {
		r, err := k.limiter.Check(ctx, k.key)
		if err != nil {
			return nil, err
		}
		if !r.Allowed {
			s.cfg.Metrics.Inc(metrics.RateLimited)
			s.audit(ctx, audit.Event{
				Type:     audit.EventRateLimited,
				Provider: req.Provider,
				ClientIP: req.Client.IP,
				Message:  "attempt throttled",
				Attrs:    map[string]string{"scope": k.scope},
			})
			return nil, &RateLimitError{RetryAfter: r.RetryAfter}
		}
	}

	identity, err := prov.Authenticate(ctx, req.Params)
	if errors.Is(err, provider.ErrInvalidCredentials) {
		for _, k := range keys {
			s.recordFailure(ctx, req, k)
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if k.scope == "login" {
			_ = k.limiter.Reset(ctx, k.key)
		}
	}
	return identity, nil
}

type limitKey struct {
	limiter ratelimit.Limiter
	scope   string // "login" or "ip"; never contains the login itself
	key     string
}

func (s *service) limitKeys(req AuthRequest) []limitKey {
	var keys []limitKey
	if l := s.cfg.RateLimit.PerLogin; l != nil {
		if login := strings.ToLower(strings.TrimSpace(req.Params["username"])); login != "" {
			keys = append(keys, limitKey{l, "login", "login:" + req.Provider + ":" + login})
		}
	}
	if l := s.cfg.RateLimit.PerIP; l != nil && req.Client.IP != "" {
		keys = append(keys, limitKey{l, "ip", "ip:" + req.Client.IP})
	}
	return keys
}

func (s *service) recordFailure(ctx context.Context, req AuthRequest, k limitKey) {
	before, _ := k.limiter.Check(ctx, k.key)
	r, err := k.limiter.Fail(ctx, k.key)
	if err != nil {
		return
	}
	hooks := s.cfg.RateLimit.Hooks
	if hooks != nil {
		hooks.OnFailure(ctx, k.key, r)
	}
	if before.Allowed && !r.Allowed {
		if hooks != nil {
			hooks.OnBlocked(ctx, k.key, r)
		}
		s.audit(ctx, audit.Event{
			Type:     audit.EventLockout,
			Provider: req.Provider,
			ClientIP: req.Client.IP,
			Message:  "too many failures; throttling",
			Attrs: map[string]string{
				"scope":       k.scope,
				"failures":    strconv.Itoa(r.Failures),
				"retry_after": r.RetryAfter.String(),
			},
		})
	}
}

// sessionSubject loads the active subject of a valid session. When the
// subject no longer exists or is disabled, the session is revoked and
// ErrInvalidSession is returned. Any other failure is a store problem: it
// is returned wrapped in ErrUnavailable and the session is kept, so a
// transient outage does not sign the user out.
func (s *service) sessionSubject(ctx context.Context, sess *session.Session) (*Subject, error) {
	subject, err := s.loadActiveSubject(ctx, sess.SubjectID)
	switch {
	case err == nil:
		return subject, nil
	case subjectGone(err):
		_ = s.sessions.RevokeByID(ctx, sess.SubjectID, sess.ID)
		return nil, ErrInvalidSession
	default:
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
}

// subjectGone reports whether err means the subject can no longer hold a
// session (deleted or disabled), as opposed to a store failure.
func subjectGone(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrSubjectDisabled)
}

// sessionError keeps session.ErrInvalid as it is and wraps every other
// session-store failure in ErrUnavailable.
func sessionError(err error) error {
	if err == nil || errors.Is(err, session.ErrInvalid) || errors.Is(err, ErrUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// loadActiveSubject loads a subject and rejects disabled ones.
func (s *service) loadActiveSubject(ctx context.Context, subjectID string) (*Subject, error) {
	subject, err := s.cfg.Users.LoadSubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	if subject.Disabled {
		return nil, ErrSubjectDisabled
	}
	return subject, nil
}

func claimsFor(subject *Subject, sessionID string) token.Claims {
	return token.Claims{
		SubjectID: subject.ID,
		SessionID: sessionID,
		Roles:     subject.Roles,
		Attrs:     subject.Attrs,
	}
}

func infoFor(sess *session.Session) SessionInfo {
	return SessionInfo{
		ID:         sess.ID,
		SubjectID:  sess.SubjectID,
		Mode:       sess.Mode,
		CreatedAt:  sess.CreatedAt,
		LastUsedAt: sess.LastUsedAt,
		ExpiresAt:  sess.ExpiresAt,
		IP:         sess.Attrs["ip"],
		UserAgent:  sess.Attrs["user_agent"],
		Provider:   sess.Attrs["provider"],
		MFA:        sess.Attrs["mfa"] != "",
	}
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, ErrUnknownIdentity):
		return "unknown_identity"
	case errors.Is(err, ErrSubjectDisabled):
		return "subject_disabled"
	case errors.Is(err, ErrNotFound):
		return "subject_not_found"
	default:
		return "store_error"
	}
}
