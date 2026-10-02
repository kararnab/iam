package iam

import (
	"context"

	"github.com/kararnab/iam/policy"
)

// Subject represents an authenticated principal in the system.
// This is the ONLY identity shape business code should see.
type Subject struct {
	ID    string            // canonical internal user ID
	Roles []string          // coarse-grained roles (optional)
	Attrs map[string]string // extensible attributes (org, tier, tier_level, etc)
}

// AuthResult is returned after a successful authentication.
// It contains both tokens and the resolved subject.
type AuthResult struct {
	AccessToken  string
	RefreshToken string
	Subject      Subject
}

// Service defines the IAM capability exposed to the application.
// This interface intentionally hides providers, tokens, sessions,
// and storage so IAM can later be:
//   - extracted into a microservice
//   - replaced with a remote client
//   - wrapped with HTTP / gRPC
type Service interface {

	// Authenticate validates credentials using a provider
	// and establishes a session.
	//
	// Expected flow:
	//   - Resolve provider
	//   - Authenticate identity
	//   - Normalize subject
	//   - Create session (refresh token)
	//   - Issue access token
	//
	// TODO:
	//   - MFA / step-up authentication
	//   - Risk-based auth
	//   - Device binding
	Authenticate(
		ctx context.Context,
		req AuthRequest,
	) (*AuthResult, error)

	// Authorize evaluates whether a subject may perform an action on a resource.
	Authorize(
		ctx context.Context,
		subject *Subject,
		action policy.Action,
		resource policy.ResourceContext,
	) (*policy.Decision, error)

	// Refresh issues a new access token using a refresh token.
	//
	// Expected flow:
	//   - Validate refresh token (stateful)
	//   - Check session validity / revocation
	//   - Rotate refresh token (optional)
	//   - Issue new access token
	//
	// TODO:
	//   - Refresh token rotation
	//   - Reuse detection
	//   - Session invalidation hooks
	Refresh(
		ctx context.Context,
		refreshToken string,
	) (string, error)

	// VerifyAccessToken validates an access token and extracts the subject.
	//
	// This is used by:
	//   - HTTP middleware
	//   - gRPC interceptors
	//   - Background jobs acting on behalf of a user
	//
	VerifyAccessToken(
		ctx context.Context,
		accessToken string,
	) (*Subject, error)

	// Revoke invalidates a refresh token (session).
	Revoke(
		ctx context.Context,
		refreshToken string,
	) error
}

// AuthRequest represents a generic authentication attempt.
// Different providers interpret Params differently.
//
// Examples:
//
//	Google OAuth:
//	  Provider = "google"
//	  Params   = { "code": "<oauth_code>" }
//
//	Internal auth:
//	  Provider = "internal"
//	  Params   = { "username": "...", "password": "..." }
type AuthRequest struct {
	Provider string            // "google", "keycloak", "internal", etc
	Params   map[string]string // provider-specific inputs
}
