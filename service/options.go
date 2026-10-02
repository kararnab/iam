package service

import (
	"github.com/kararnab/iam"
	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/metrics"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token"
)

// Options defines all dependencies required by the IAM service.
//
// Every dependency is injected explicitly.
// This is what makes the implementation pluggable.
type Options struct {
	Providers map[string]provider.AuthProvider

	// Users resolves provider identities to canonical subjects and loads
	// their roles. Implemented by the application.
	Users iam.UserStore

	SessionManager session.Manager
	SessionStore   session.Store

	TokenIssuer   token.Issuer
	TokenVerifier token.Verifier

	PolicyEngine policy.Engine
	AuditLogger  audit.Logger
	Metrics      metrics.IAMMetrics
}
