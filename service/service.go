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
				"reason": err.Error(),
			},
		})
		return "", err
	}

	claims := token.Claims{
		SubjectID: sess.SubjectID,
	}

	accessToken, err := s.opts.TokenIssuer.Issue(ctx, claims)
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

	subject := iam.Subject{
		ID:    identity.ProviderID,
		Roles: identity.Roles, // []string{policy.Admin} or nil, this role defines what the user will be able to access (RBAC)
		Attrs: identity.Attrs,
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

	accessToken, err := s.opts.TokenIssuer.Issue(
		ctx,
		token.Claims{
			SubjectID: subject.ID,
			Roles:     subject.Roles,
			Attrs:     subject.Attrs,
		},
	)
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
		Subject:      subject,
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
