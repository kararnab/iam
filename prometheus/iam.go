package prometheus

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/kararnab/iam/metrics"
)

const (
	namespace = "iam"
	subsystem = "iam"
)

type IAMMetrics struct {
	authSuccess prometheus.Counter
	authFailure prometheus.Counter

	verifySuccess prometheus.Counter
	verifyFailure prometheus.Counter

	refreshSuccess prometheus.Counter
	refreshFailure prometheus.Counter

	sessionRevokeSuccess prometheus.Counter
	sessionRevokeFailure prometheus.Counter

	policyDenied prometheus.Counter
}

func NewIAMMetrics(reg prometheus.Registerer) metrics.IAMMetrics {

	m := &IAMMetrics{
		authSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "auth_success_total",
			Help:      "Successful authentication attempts",
		}),
		authFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "auth_failure_total",
			Help:      "Failed authentication attempts",
		}),
		verifySuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "token_verify_success_total",
			Help:      "Successful access token verifications",
		}),
		verifyFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "token_verify_failure_total",
			Help:      "Failed access token verifications",
		}),
		refreshSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "token_refresh_success_total",
			Help:      "Successful refresh token operations",
		}),
		refreshFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "token_refresh_failure_total",
			Help:      "Failed refresh token operations",
		}),
		sessionRevokeSuccess: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "session_revoke_success_total",
			Help:      "Successful revoke session operations",
		}),
		sessionRevokeFailure: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "session_revoke_failure_total",
			Help:      "Failed revoke session operations",
		}),
		policyDenied: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "policy_denied_total",
			Help:      "Authorization denials by policy engine",
		}),
	}

	reg.MustRegister(
		m.authSuccess,
		m.authFailure,
		m.verifySuccess,
		m.verifyFailure,
		m.refreshSuccess,
		m.refreshFailure,
		m.sessionRevokeSuccess,
		m.sessionRevokeFailure,
		m.policyDenied,
	)

	return m
}

// --- Interface implementation ---

func (m *IAMMetrics) AuthSuccess()          { m.authSuccess.Inc() }
func (m *IAMMetrics) AuthFailure()          { m.authFailure.Inc() }
func (m *IAMMetrics) TokenVerifySuccess()   { m.verifySuccess.Inc() }
func (m *IAMMetrics) TokenVerifyFailure()   { m.verifyFailure.Inc() }
func (m *IAMMetrics) TokenRefreshSuccess()  { m.refreshSuccess.Inc() }
func (m *IAMMetrics) TokenRefreshFailure()  { m.refreshFailure.Inc() }
func (m *IAMMetrics) SessionRevokeSuccess() { m.sessionRevokeSuccess.Inc() }
func (m *IAMMetrics) SessionRevokeFailure() { m.sessionRevokeFailure.Inc() }
func (m *IAMMetrics) PolicyDenied()         { m.policyDenied.Inc() }
