package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/provider/inhouse"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token/jwt"
	"github.com/kararnab/iam/token/keys"
)

type fakeUsers map[string]*inhouse.User

func (f fakeUsers) GetByUsername(_ context.Context, u string) (*inhouse.User, error) {
	if user, ok := f[u]; ok {
		return user, nil
	}
	return nil, errors.New("not found")
}

func (f fakeUsers) Create(_ context.Context, u *inhouse.User) error {
	f[u.Email] = u
	return nil
}

type nopAudit struct{}

func (nopAudit) Log(context.Context, audit.Event) error { return nil }

type nopMetrics struct{}

func (nopMetrics) AuthSuccess()          {}
func (nopMetrics) AuthFailure()          {}
func (nopMetrics) TokenVerifySuccess()   {}
func (nopMetrics) TokenVerifyFailure()   {}
func (nopMetrics) TokenRefreshSuccess()  {}
func (nopMetrics) TokenRefreshFailure()  {}
func (nopMetrics) SessionRevokeSuccess() {}
func (nopMetrics) SessionRevokeFailure() {}
func (nopMetrics) PolicyDenied()         {}

func newTestService(t *testing.T) *Service {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	users := fakeUsers{"admin@example.com": {
		ID: "u1", Email: "admin@example.com", PasswordHash: string(hash), Roles: []string{policy.Admin},
	}}
	kp := keys.NewMemoryProvider(keys.Key{ID: "k1", Alg: keys.HS256, Secret: []byte("0123456789abcdef0123456789abcdef")})
	jwtCfg := jwt.Config{Issuer: "test", Audience: "test-api", TTL: time.Minute}
	issuer, err := jwt.NewIssuer(kp, jwtCfg)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := jwt.NewVerifier(kp, jwtCfg)
	if err != nil {
		t.Fatal(err)
	}
	store := session.NewMemoryStore()
	prov := inhouse.New(users)
	svc, err := New(Options{
		Providers:      map[string]provider.AuthProvider{prov.Name(): prov},
		SessionManager: session.NewManager(store, time.Hour),
		SessionStore:   store,
		TokenIssuer:    issuer,
		TokenVerifier:  verifier,
		PolicyEngine:   &policy.DefaultPolicy{},
		AuditLogger:    nopAudit{},
		Metrics:        nopMetrics{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// TestCurrentFlows pins the behaviour before the library restructure.
func TestCurrentFlows(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	if _, err := svc.Authenticate(ctx, iam.AuthRequest{Provider: "internal", Params: map[string]string{
		"username": "admin@example.com", "password": "wrong",
	}}); err == nil {
		t.Fatal("wrong password accepted")
	}

	res, err := svc.Authenticate(ctx, iam.AuthRequest{Provider: "internal", Params: map[string]string{
		"username": "admin@example.com", "password": "pw",
	}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	sub, err := svc.VerifyAccessToken(ctx, res.AccessToken)
	if err != nil || sub.ID != "u1" || len(sub.Roles) != 1 {
		t.Fatalf("verify: %v %+v", err, sub)
	}

	dec, err := svc.Authorize(ctx, sub, "rotate", policy.ResourceContext{Type: policy.Admin})
	if err != nil || dec.Effect != policy.EffectAllow {
		t.Fatalf("admin authorize: %v %+v", err, dec)
	}

	if _, err := svc.Refresh(ctx, res.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := svc.Revoke(ctx, res.RefreshToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Refresh(ctx, res.RefreshToken); err == nil {
		t.Fatal("refresh after revoke succeeded")
	}
}
