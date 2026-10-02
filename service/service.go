package service

import (
	"context"
	"errors"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/token"
)

// Service is the default IAM service implementation.
//
// It orchestrates:
//   - identity providers
//   - session lifecycle
//   - token issuance / verification
//   - policy evaluation
//   - audit logging
//
// It contains NO business logic and NO provider-specific code.
type Service struct {
	opts Options
}

// New creates a new IAM service with pluggable dependencies.
func New(opts Options) (*Service, error) {
	if len(opts.Providers) == 0 {
		return nil, errors.New("iam: at least one provider must be configured")
	}
	if opts.Users == nil {
		return nil, errors.New("iam: user store is required")
	}
	if opts.SessionManager == nil || opts.SessionStore == nil {
		return nil, errors.New("iam: session manager and store are required")
	}
	if opts.TokenIssuer == nil || opts.TokenVerifier == nil {
		return nil, errors.New("iam: token issuer and verifier are required")
	}
	if opts.PolicyEngine == nil {
		return nil, errors.New("iam: policy engine is required")
	}
	if opts.AuditLogger == nil {
		return nil, errors.New("iam: audit logger is required")
	}

	return &Service{opts: opts}, nil
}

func (s *Service) Refresh(
	ctx context.Context,
	refreshToken string,
) (string, error) {

	sess, err := s.opts.SessionManager.Validate(ctx, refreshToken)
	if err != nil {
		s.opts.Metrics.TokenRefreshFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:    audit.EventTokenRefresh,
			Message: "refresh failed",
			Attrs: map[string]string{
				"reason": "invalid_session",
			},
		})
		return "", err
	}

	// Reload the subject so roles and attributes are current, and so a
	// disabled or deleted subject cannot keep refreshing.
	subject, err := s.loadActiveSubject(ctx, sess.SubjectID)
	if err != nil {
		_ = s.opts.SessionManager.Revoke(ctx, refreshToken)
		s.opts.Metrics.TokenRefreshFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:      audit.EventTokenRefresh,
			SubjectID: sess.SubjectID,
			Message:   "refresh failed",
			Attrs:     map[string]string{"reason": "subject_unavailable"},
		})
		return "", err
	}

	accessToken, err := s.opts.TokenIssuer.Issue(ctx, claimsFor(subject))
	if err != nil {
		return "", err
	}

	s.opts.Metrics.TokenRefreshSuccess()
	_ = s.opts.AuditLogger.Log(ctx, audit.Event{
		Type:      audit.EventTokenRefresh,
		SubjectID: sess.SubjectID,
		Message:   "token refreshed",
	})

	return accessToken, nil
}

func (s *Service) Authenticate(
	ctx context.Context,
	req iam.AuthRequest,
) (*iam.AuthResult, error) {

	prov, ok := s.opts.Providers[req.Provider]
	if !ok {
		s.opts.Metrics.AuthFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:     audit.EventAuthFailure,
			Provider: req.Provider,
			Message:  "unknown auth provider",
		})
		return nil, errors.New("iam: unknown provider")
	}

	identity, err := prov.Authenticate(ctx, req.Params)
	if err != nil {
		s.opts.Metrics.AuthFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:     audit.EventAuthFailure,
			Provider: req.Provider,
			Message:  "authentication failed",
			Attrs: map[string]string{
				"reason": "provider_auth_failed",
			},
		})
		return nil, err
	}

	subjectID, err := s.opts.Users.ResolveIdentity(ctx, identity.Provider, identity.ProviderID)
	if errors.Is(err, iam.ErrNotFound) {
		err = iam.ErrUnknownIdentity
	}
	var subject *iam.Subject
	if err == nil {
		subject, err = s.loadActiveSubject(ctx, subjectID)
	}
	if err != nil {
		s.opts.Metrics.AuthFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:      audit.EventAuthFailure,
			SubjectID: subjectID,
			Provider:  req.Provider,
			Message:   "authentication failed",
			Attrs:     map[string]string{"reason": reasonFor(err)},
		})
		return nil, err
	}

	session, err := s.opts.SessionManager.Create(ctx, subject.ID, nil)
	if err != nil {
		s.opts.Metrics.AuthFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:      audit.EventAuthFailure,
			SubjectID: subject.ID,
			Provider:  req.Provider,
			Message:   "session creation failed",
		})
		return nil, err
	}

	accessToken, err := s.opts.TokenIssuer.Issue(ctx, claimsFor(subject))
	if err != nil {
		return nil, err
	}

	s.opts.Metrics.AuthSuccess()
	_ = s.opts.AuditLogger.Log(ctx, audit.Event{
		Type:      audit.EventAuthSuccess,
		SubjectID: subject.ID,
		Provider:  req.Provider,
		Message:   "authentication successful",
	})

	return &iam.AuthResult{
		AccessToken:  accessToken,
		RefreshToken: session.ID,
		Subject:      *subject,
	}, nil
}

func (s *Service) Authorize(
	ctx context.Context,
	subject *iam.Subject,
	action policy.Action,
	resource policy.ResourceContext,
) (*policy.Decision, error) {

	decision, err := s.opts.PolicyEngine.Evaluate(
		ctx,
		policy.SubjectContext{
			SubjectID: subject.ID,
			Roles:     subject.Roles,
			Attrs:     subject.Attrs,
		},
		action,
		resource,
	)
	if err != nil {
		s.opts.Metrics.PolicyDenied()
		return nil, err
	}

	if decision.Effect == policy.EffectDeny {
		s.opts.Metrics.PolicyDenied()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:      audit.EventPolicyDenied,
			SubjectID: subject.ID,
			Message:   decision.Reason,
		})
	}

	return decision, nil
}

func (s *Service) VerifyAccessToken(
	ctx context.Context,
	accessToken string,
) (*iam.Subject, error) {

	claims, err := s.opts.TokenVerifier.Verify(ctx, accessToken)
	if err != nil {
		s.opts.Metrics.TokenVerifyFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:    audit.EventTokenVerifyFailure,
			Message: "access token verification failed",
		})
		return nil, err
	}

	s.opts.Metrics.TokenVerifySuccess()

	subject := &iam.Subject{
		ID:    claims.SubjectID,
		Roles: claims.Roles,
		Attrs: claims.Attrs,
	}

	return subject, nil
}

func (s *Service) Revoke(
	ctx context.Context,
	refreshToken string,
) error {

	if err := s.opts.SessionManager.Revoke(ctx, refreshToken); err != nil {
		s.opts.Metrics.SessionRevokeFailure()
		_ = s.opts.AuditLogger.Log(ctx, audit.Event{
			Type:    audit.EventSessionRevoked,
			Message: "session revoke failed",
		})
		return err
	}

	s.opts.Metrics.SessionRevokeSuccess()
	_ = s.opts.AuditLogger.Log(ctx, audit.Event{
		Type:    audit.EventSessionRevoked,
		Message: "session revoked",
	})

	return nil
}

func (s *Service) LinkIdentity(
	ctx context.Context,
	subjectID string,
	req iam.AuthRequest,
) error {

	if _, err := s.loadActiveSubject(ctx, subjectID); err != nil {
		return err
	}

	prov, ok := s.opts.Providers[req.Provider]
	if !ok {
		return errors.New("iam: unknown provider")
	}
	identity, err := prov.Authenticate(ctx, req.Params)
	if err != nil {
		return err
	}

	owner, err := s.opts.Users.ResolveIdentity(ctx, identity.Provider, identity.ProviderID)
	switch {
	case err == nil && owner == subjectID:
		return nil // already linked to this subject
	case err == nil:
		return iam.ErrIdentityLinked
	case !errors.Is(err, iam.ErrNotFound):
		return err
	}

	if err := s.opts.Users.LinkIdentity(ctx, subjectID, *identity); err != nil {
		if errors.Is(err, iam.ErrConflict) {
			return iam.ErrIdentityLinked // lost a race with another link
		}
		return err
	}

	_ = s.opts.AuditLogger.Log(ctx, audit.Event{
		Type:      audit.EventIdentityLinked,
		SubjectID: subjectID,
		Provider:  identity.Provider,
		Message:   "identity linked",
	})
	return nil
}

// loadActiveSubject loads a subject and rejects disabled ones.
func (s *Service) loadActiveSubject(ctx context.Context, subjectID string) (*iam.Subject, error) {
	subject, err := s.opts.Users.LoadSubject(ctx, subjectID)
	if err != nil {
		return nil, err
	}
	if subject.Disabled {
		return nil, iam.ErrSubjectDisabled
	}
	return subject, nil
}

func claimsFor(subject *iam.Subject) token.Claims {
	return token.Claims{
		SubjectID: subject.ID,
		Roles:     subject.Roles,
		Attrs:     subject.Attrs,
	}
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, iam.ErrUnknownIdentity):
		return "unknown_identity"
	case errors.Is(err, iam.ErrSubjectDisabled):
		return "subject_disabled"
	case errors.Is(err, iam.ErrNotFound):
		return "subject_not_found"
	default:
		return "store_error"
	}
}
