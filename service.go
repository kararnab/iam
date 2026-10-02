package iam

import (
	"context"
	"errors"
	"strconv"

	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token"
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
		s.cfg.Metrics.AuthFailure()
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

	prov, ok := s.providers[req.Provider]
	if !ok {
		return fail("", "unknown_provider", ErrUnknownProvider)
	}

	identity, err := prov.Authenticate(ctx, req.Params)
	if err != nil {
		return fail("", "invalid_credentials", err)
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

	res, err := s.startSession(ctx, subject, mode, identity.Provider, req.Client)
	if err != nil {
		return fail(subject.ID, "session_error", err)
	}

	s.cfg.Metrics.AuthSuccess()
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
func (s *service) startSession(ctx context.Context, subject *Subject, mode session.Mode, providerName string, client ClientInfo) (*LoginResult, error) {
	attrs := map[string]string{"provider": providerName}
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
		s.cfg.Metrics.TokenRefreshFailure()
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

	sess, newRefresh, err := s.sessions.Refresh(ctx, refreshToken)
	switch {
	case errors.Is(err, session.ErrReused):
		return fail(sess, audit.EventRefreshReuse, "reuse", err)
	case errors.Is(err, session.ErrRaced):
		return fail(sess, audit.EventRefreshFailure, "raced", err)
	case err != nil:
		return fail(nil, audit.EventRefreshFailure, "invalid_session", err)
	}

	// Reload the subject so roles and attributes are current, and so a
	// disabled or deleted subject cannot keep refreshing.
	subject, err := s.loadActiveSubject(ctx, sess.SubjectID)
	if err != nil {
		_ = s.sessions.RevokeByID(ctx, sess.SubjectID, sess.ID)
		return fail(sess, audit.EventRefreshFailure, reasonFor(err), err)
	}

	at, err := s.cfg.TokenIssuer.Issue(ctx, claimsFor(subject, sess.ID))
	if err != nil {
		return fail(sess, audit.EventRefreshFailure, "issue_error", err)
	}

	s.cfg.Metrics.TokenRefreshSuccess()
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
		s.cfg.Metrics.TokenVerifyFailure()
		s.audit(ctx, audit.Event{
			Type:    audit.EventTokenVerifyFailure,
			Message: "access token verification failed",
		})
		return nil, nil, err
	}

	info := &SessionInfo{ID: claims.SessionID, SubjectID: claims.SubjectID, Mode: session.ModeBearer}
	if s.cfg.VerifySessionOnAccess {
		sess, err := s.sessions.Get(ctx, claims.SessionID)
		if err != nil || sess.SubjectID != claims.SubjectID || sess.Mode != session.ModeBearer {
			s.cfg.Metrics.TokenVerifyFailure()
			return nil, nil, ErrInvalidSession
		}
		*info = infoFor(sess)
	}

	s.cfg.Metrics.TokenVerifySuccess()
	return &Subject{ID: claims.SubjectID, Roles: claims.Roles, Attrs: claims.Attrs}, info, nil
}

// ---------------------------------------------------------------------------
// Cookie mode
// ---------------------------------------------------------------------------

func (s *service) ValidateSession(ctx context.Context, sessionToken string) (*Subject, *SessionInfo, error) {
	sess, err := s.sessions.Validate(ctx, sessionToken)
	if err != nil {
		return nil, nil, err
	}
	subject, err := s.loadActiveSubject(ctx, sess.SubjectID)
	if err != nil {
		_ = s.sessions.RevokeByID(ctx, sess.SubjectID, sess.ID)
		return nil, nil, ErrInvalidSession
	}
	info := infoFor(sess)
	return subject, &info, nil
}

func (s *service) RotateSession(ctx context.Context, sessionToken string) (*LoginResult, error) {
	sess, secret, err := s.sessions.Rotate(ctx, sessionToken)
	if err != nil {
		return nil, err
	}
	subject, err := s.loadActiveSubject(ctx, sess.SubjectID)
	if err != nil {
		_ = s.sessions.RevokeByID(ctx, sess.SubjectID, sess.ID)
		return nil, ErrInvalidSession
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
		s.cfg.Metrics.SessionRevokeFailure()
		return err
	}
	if sess == nil {
		return nil
	}
	s.cfg.Metrics.SessionRevokeSuccess()
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
	s.cfg.Metrics.SessionRevokeSuccess()
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
		s.cfg.Metrics.PolicyDenied()
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

	prov, ok := s.providers[req.Provider]
	if !ok {
		return ErrUnknownProvider
	}
	identity, err := prov.Authenticate(ctx, req.Params)
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
