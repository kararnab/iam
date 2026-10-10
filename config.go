package iam

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/metrics"
	"github.com/kararnab/iam/v2/mfa"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/ratelimit"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/token"
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

// RecoveryConfig enables password reset and email verification (see
// Recovery). Both are off until Tokens is set.
type RecoveryConfig struct {
	// Tokens stores reset and verification tokens. Required for Recovery.
	Tokens onetime.Store

	// PasswordProvider names the provider whose passwords are reset. It must
	// implement provider.PasswordSetter. Default "password"; when no
	// provider has that name, only email verification is available.
	PasswordProvider string

	// ResetTTL is the lifetime of a password-reset token. Default 1 hour,
	// max 24 hours.
	ResetTTL time.Duration

	// VerificationTTL is the lifetime of an email-verification token.
	// Default 48 hours, max 30 days.
	VerificationTTL time.Duration
}

// MFAConfig enables TOTP multi-factor authentication (see MFA). It is off
// until Store is set.
type MFAConfig struct {
	// Store keeps each subject's TOTP factor.
	Store mfa.Store

	// Key seals TOTP secrets at rest and login challenges; at least 32
	// bytes. Changing it makes every enrolled factor unusable, so keep it
	// with your other long-lived secrets.
	Key []byte

	// Issuer names your application in authenticator apps. Required.
	Issuer string

	// ChallengeTTL is how long a user has to enter their code after the
	// first factor. Default 5 minutes, max 15 minutes.
	ChallengeTTL time.Duration

	// Skew is how many 30-second steps either side of now are accepted.
	// Default 1; at most 2.
	Skew int

	// ExemptProviders are providers whose logins never ask for a code, for
	// example an OIDC issuer that enforces its own MFA.
	ExemptProviders []string
}

// RateLimitConfig throttles failed logins.
//
// When both limiters are nil and Disabled is false, in-memory limiters are
// used: 5 failures per login and 100 per IP within 15 minutes, then a
// growing back-off. With several instances, use a shared limiter such as
// redisstore.Limiter.
type RateLimitConfig struct {
	// Disabled turns throttling off. Only for tests or when an upstream
	// component already throttles logins.
	Disabled bool

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

	// LoadSubjectOnAccess makes VerifyAccessToken also load the subject
	// from Users, so roles, attributes and Disabled are current on every
	// bearer request (as they are in cookie mode) instead of being the ones
	// in the token. A revoked role or a disabled subject then takes effect
	// immediately rather than when the access token expires, at the cost of
	// a LoadSubject call per request. A subject that is gone or disabled
	// makes the token invalid and revokes its session. Default false.
	LoadSubjectOnAccess bool

	// Policy decides authorization. Required: there is no allow-all default.
	Policy policy.Engine

	// Signup controls SignUp and invites.
	Signup SignupConfig

	// RateLimit throttles failed logins, and password-reset requests.
	RateLimit RateLimitConfig

	// Recovery enables password reset and email verification.
	Recovery RecoveryConfig

	// MFA enables TOTP multi-factor authentication.
	MFA MFAConfig

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

	if err := c.Recovery.validate(c.Providers); err != nil {
		return err
	}
	if err := c.MFA.validate(); err != nil {
		return err
	}

	if !c.RateLimit.Disabled && c.RateLimit.PerLogin == nil && c.RateLimit.PerIP == nil {
		var err error
		if c.RateLimit.PerLogin, err = ratelimit.NewMemory(ratelimit.Config{Threshold: 5}); err != nil {
			return err
		}
		if c.RateLimit.PerIP, err = ratelimit.NewMemory(ratelimit.Config{Threshold: 100}); err != nil {
			return err
		}
	}
	if c.RateLimit.Disabled {
		c.RateLimit.PerLogin, c.RateLimit.PerIP = nil, nil
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

func (c *RecoveryConfig) validate(providers []provider.AuthProvider) error {
	explicit := c.PasswordProvider != ""
	if !explicit {
		c.PasswordProvider = "password"
	}
	for _, p := range providers {
		if p.Name() == c.PasswordProvider {
			if _, ok := p.(provider.PasswordSetter); !ok {
				return fmt.Errorf("iam: provider %q cannot set passwords (provider.PasswordSetter)", p.Name())
			}
			explicit = false
		}
	}
	if explicit {
		return fmt.Errorf("iam: Recovery.PasswordProvider %q is not configured", c.PasswordProvider)
	}

	if c.ResetTTL == 0 {
		c.ResetTTL = time.Hour
	}
	if c.ResetTTL < 0 || c.ResetTTL > 24*time.Hour {
		return errors.New("iam: Recovery.ResetTTL must be between 0 and 24 hours")
	}
	if c.VerificationTTL == 0 {
		c.VerificationTTL = 48 * time.Hour
	}
	if c.VerificationTTL < 0 || c.VerificationTTL > 30*24*time.Hour {
		return errors.New("iam: Recovery.VerificationTTL must be between 0 and 30 days")
	}
	return nil
}

func (c *MFAConfig) validate() error {
	if c.Store == nil {
		return nil
	}
	if len(c.Key) < 32 {
		return errors.New("iam: MFA.Key must be at least 32 bytes")
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return errors.New("iam: MFA.Issuer is required")
	}
	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = 5 * time.Minute
	}
	if c.ChallengeTTL < 0 || c.ChallengeTTL > 15*time.Minute {
		return errors.New("iam: MFA.ChallengeTTL must be between 0 and 15 minutes")
	}
	if c.Skew == 0 {
		c.Skew = 1
	}
	if c.Skew < 0 || c.Skew > 2 {
		return errors.New("iam: MFA.Skew must be 1 or 2")
	}
	return nil
}
