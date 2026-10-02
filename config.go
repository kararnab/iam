package iam

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/metrics"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token"
)

var (
	// ErrUnknownProvider is returned when AuthRequest.Provider is not configured.
	ErrUnknownProvider = errors.New("iam: unknown provider")

	// ErrModeNotAllowed is returned when a login asks for a session mode
	// that is not in Config.AllowedModes.
	ErrModeNotAllowed = errors.New("iam: session mode not allowed")
)

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

	// Audit receives security events. Default: audit.SlogLogger.
	Audit audit.Logger

	// Metrics receives counters. Default: metrics.Noop.
	Metrics metrics.IAMMetrics

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
