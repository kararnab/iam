// Package iam is a provider-agnostic, token-format-agnostic authentication
// and authorization library.
//
// The application talks to the Service interface only. New returns the
// default, in-process implementation; because every method takes and returns
// plain data, the same interface can later be served by a remote IAM.
//
// IAM owns sessions, tokens, policy evaluation and audit events. The
// application owns users: it implements UserStore (subjects, roles and
// linked identities) and decides how sign-in is presented.
package iam

import (
	"context"
	"time"

	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
)

// Subject represents an authenticated principal in the system.
// This is the ONLY identity shape business code should see.
//
// ID is the application's canonical subject ID. It is never a provider's
// user ID: one subject may sign in through several providers (see
// IdentityStore).
type Subject struct {
	ID    string            `json:"id"`              // canonical internal subject ID
	Roles []string          `json:"roles,omitempty"` // coarse-grained roles, owned by the application
	Attrs map[string]string `json:"attrs,omitempty"` // extensible attributes (org, tier, etc)

	// Disabled subjects cannot log in, and their sessions stop working.
	Disabled bool `json:"-"`
}

// ClientInfo describes the client making a request. The HTTP layer fills it
// in; IAM uses it for audit events, session listings and rate limiting.
type ClientInfo struct {
	IP        string
	UserAgent string
}

// AuthRequest represents an authentication attempt.
// Different providers interpret Params differently.
//
// Examples:
//
//	OIDC / Google:
//	  Provider = "google"
//	  Params   = { "id_token": "<id token>" }
//
//	Password:
//	  Provider = "password"
//	  Params   = { "username": "...", "password": "..." }
type AuthRequest struct {
	Provider string            // provider name
	Params   map[string]string // provider-specific inputs
	Mode     session.Mode      // empty means the first of Config.AllowedModes
	Client   ClientInfo
}

// SessionInfo describes a session without its secret.
type SessionInfo struct {
	ID         string       `json:"id"` // public session ID
	SubjectID  string       `json:"subject_id"`
	Mode       session.Mode `json:"mode"`
	CreatedAt  time.Time    `json:"created_at,omitzero"`
	LastUsedAt time.Time    `json:"last_used_at,omitzero"`
	ExpiresAt  time.Time    `json:"expires_at,omitzero"`
	IP         string       `json:"ip,omitempty"`
	UserAgent  string       `json:"user_agent,omitempty"`
	Provider   string       `json:"provider,omitempty"`
}

// LoginResult is returned by a successful login.
//
// In cookie mode only SessionToken is set; it belongs in an HttpOnly cookie
// and is deliberately excluded from JSON. In bearer mode AccessToken and
// RefreshToken are set.
type LoginResult struct {
	Mode         session.Mode `json:"mode"`
	SessionToken string       `json:"-"`
	AccessToken  string       `json:"access_token,omitempty"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	Subject      Subject      `json:"subject"`
	Session      SessionInfo  `json:"session"`
}

// TokenPair is returned by Refresh. The refresh token always rotates.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// Service defines the IAM capability exposed to the application.
// This interface intentionally hides providers, tokens, sessions,
// and storage so IAM can later be:
//   - extracted into a microservice
//   - replaced with a remote client
//   - wrapped with HTTP / gRPC
type Service interface {
	// Login authenticates through a provider, resolves the canonical
	// subject and starts a session in the requested mode.
	Login(ctx context.Context, req AuthRequest) (*LoginResult, error)

	// Refresh rotates a bearer-mode refresh token and issues a new access
	// token with the subject's current roles. Reusing a rotated refresh
	// token revokes the session and returns ErrRefreshReused.
	Refresh(ctx context.Context, refreshToken string, client ClientInfo) (*TokenPair, error)

	// ValidateSession checks a cookie-mode session token and returns the
	// subject, freshly loaded from the application's store.
	ValidateSession(ctx context.Context, sessionToken string) (*Subject, *SessionInfo, error)

	// VerifyAccessToken validates a bearer access token. The returned
	// SessionInfo has at least ID, SubjectID and Mode.
	VerifyAccessToken(ctx context.Context, accessToken string) (*Subject, *SessionInfo, error)

	// Authorize evaluates whether a subject may perform an action on a
	// resource. Engine errors and missing subjects result in a deny.
	Authorize(ctx context.Context, subject *Subject, action policy.Action, resource policy.Resource) (*policy.Decision, error)

	// Logout ends the session that owns the given session token or refresh
	// token. Unknown tokens are not an error.
	Logout(ctx context.Context, token string) error

	// RotateSession replaces a cookie-mode session token, for example after
	// a privilege change. The old token stops working.
	RotateSession(ctx context.Context, sessionToken string) (*LoginResult, error)

	// ListSessions returns a subject's active sessions.
	ListSessions(ctx context.Context, subjectID string) ([]SessionInfo, error)

	// RevokeSession ends one of the subject's sessions by public ID.
	RevokeSession(ctx context.Context, subjectID, sessionID string) error

	// RevokeAllSessions ends all of a subject's sessions except
	// exceptSessionID (empty for all): "log out everywhere".
	RevokeAllSessions(ctx context.Context, subjectID, exceptSessionID string) (int, error)

	// LinkIdentity authenticates req and links the resulting provider
	// identity to an existing subject. It fails with ErrIdentityLinked if
	// the identity already belongs to a different subject.
	LinkIdentity(ctx context.Context, subjectID string, req AuthRequest) error
}

var (
	// ErrInvalidCredentials is returned (wrapped) for failed logins.
	ErrInvalidCredentials = provider.ErrInvalidCredentials

	// ErrInvalidSession is returned for unknown, expired or revoked session
	// tokens and refresh tokens.
	ErrInvalidSession = session.ErrInvalid

	// ErrRefreshReused is returned when a rotated refresh token is reused;
	// the session has been revoked.
	ErrRefreshReused = session.ErrReused

	// ErrRefreshRaced is returned when a just-rotated refresh token is
	// reused within the configured grace window; the session is kept.
	ErrRefreshRaced = session.ErrRaced
)
