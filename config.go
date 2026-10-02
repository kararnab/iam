package iam

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/invite"
	"github.com/kararnab/iam/metrics"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/ratelimit"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token"
)

var (
	// ErrUnknownProvider is returned when AuthRequest.Provider is not configured.
	ErrUnknownProvider = errors.New("iam: unknown provider")

	// ErrModeNotAllowed is returned when a login asks for a session mode
	// that is not in Config.AllowedModes.
	ErrModeNotAllowed = errors.New("iam: session mode not allowed")

	// ErrSignupClosed is returned by SignUp when the sign-up policy is Closed.
	ErrSignupClosed = errors.New("iam: sign-up is closed")

	// ErrInvalidInvite is returned for unknown, used, expired or
	// mismatched invites.
	ErrInvalidInvite = invite.ErrInvalid

	// ErrAlreadyRegistered is returned by SignUp when the identity is
	// already linked to a subject.
	ErrAlreadyRegistered = errors.New("iam: identity is already registered")

	// ErrRateLimited is wrapped by *RateLimitError.
	ErrRateLimited = errors.New("iam: too many attempts")
)

// RateLimitError is returned when an attempt is throttled. It wraps
// ErrRateLimited and says when to retry.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("iam: too many attempts; retry after %s", e.RetryAfter.Round(time.Second))
}

func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

// SignupConfig controls SignUp and invites.
type SignupConfig struct {
	// Policy: invite.Closed, invite.InviteOnly or invite.Open. Default:
	// InviteOnly when Invites is set, otherwise Closed.
	Policy invite.Policy

	// Invites stores invitations. Required for InviteOnly.
	Invites invite.Store

	// DefaultRoles are granted on open sign-up (invites carry their own).
	DefaultRoles []string

	// InviteTTL is the default invite lifetime. Default 7 days, max 90 days.
	InviteTTL time.Duration
}

// RateLimitConfig throttles failed logins. Nil limiters disable that check.
type RateLimitConfig struct {
	// PerLogin counts failures per provider and login name
	// (key "login:<provider>:<login>").
	PerLogin ratelimit.Limiter

	// PerIP counts failures per client IP (key "ip:<ip>").
	PerIP ratelimit.Limiter

	// Hooks are told about failures and blocks, for notifications or a
	// hard lockout kept by the application.
	Hooks ratelimit.LockoutHooks
}

// Config holds every dependency of the default Service. Dependencies are
// injected explicitly; that is what makes every part replaceable.
type Config struct {
	// Providers authenticate credentials. Names must be unique.
	Providers []provider.AuthProvider

	// Users resolves identities to subjects and loads roles (application-owned).
	Users UserStore

	// Sessions persists sessions (memstore.Sessions, a database, Redis, ...).
	Sessions session.Store

	// Session tunes timeouts and refresh-token reuse handling.
	Session session.Config

	// AllowedModes lists the session modes clients may request. The first is
	// the default. Default: cookie only.
	AllowedModes []session.Mode

	// TokenIssuer and TokenVerifier mint and check access tokens. Required
	// when bearer mode is allowed.
	TokenIssuer   token.Issuer
	TokenVerifier token.Verifier

	// VerifySessionOnAccess makes VerifyAccessToken also check that the
	// token's session still exists, so revocation is immediate at the cost
	// of a store lookup per request. Default false: access tokens stay
	// valid until they expire.
	VerifySessionOnAccess bool

	// Policy decides authorization. Required: there is no allow-all default.
	Policy policy.Engine

	// Signup controls SignUp and invites.
	Signup SignupConfig

	// RateLimit throttles failed logins.
	RateLimit RateLimitConfig

	// Audit receives security events. Default: audit.SlogLogger.
	Audit audit.Logger

	// Metrics receives counters. Default: metrics.Noop.
	Metrics metrics.Recorder

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

func (c *Config) validate() error {
	if len(c.Providers) == 0 {
		return errors.New("iam: at least one provider must be configured")
	}
	seen := map[string]bool{}
	for _, p := range c.Providers {
		if p == nil || p.Name() == "" {
			return errors.New("iam: providers must be non-nil and named")
		}
		if seen[p.Name()] {
			return fmt.Errorf("iam: duplicate provider %q", p.Name())
		}
		seen[p.Name()] = true
	}
	if c.Users == nil {
		return errors.New("iam: Users is required")
	}
	if c.Sessions == nil {
		return errors.New("iam: Sessions is required")
	}
	if c.Policy == nil {
		return errors.New("iam: Policy is required (use policy.DenyAll or policy.RBAC)")
	}

	if len(c.AllowedModes) == 0 {
		c.AllowedModes = []session.Mode{session.ModeCookie}
	}
	for _, m := range c.AllowedModes {
		if !m.Valid() {
			return fmt.Errorf("iam: invalid session mode %q", m)
		}
	}
	if slices.Contains(c.AllowedModes, session.ModeBearer) && (c.TokenIssuer == nil || c.TokenVerifier == nil) {
		return errors.New("iam: TokenIssuer and TokenVerifier are required for bearer mode")
	}

	switch c.Signup.Policy {
	case "":
		c.Signup.Policy = invite.Closed
		if c.Signup.Invites != nil {
			c.Signup.Policy = invite.InviteOnly
		}
	case invite.Closed, invite.Open:
	case invite.InviteOnly:
		if c.Signup.Invites == nil {
			return errors.New("iam: Signup.Invites is required for invite-only sign-up")
		}
	default:
		return fmt.Errorf("iam: invalid sign-up policy %q", c.Signup.Policy)
	}
	if c.Signup.InviteTTL == 0 {
		c.Signup.InviteTTL = 7 * 24 * time.Hour
	}
	if c.Signup.InviteTTL < 0 || c.Signup.InviteTTL > 90*24*time.Hour {
		return errors.New("iam: Signup.InviteTTL must be between 0 and 90 days")
	}

	if c.Audit == nil {
		c.Audit = audit.NewSlogLogger(nil)
	}
	if c.Metrics == nil {
		c.Metrics = metrics.Noop{}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Session.Now == nil {
		c.Session.Now = c.Now
	}
	return nil
}
