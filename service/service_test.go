package service

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/memstore"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token/jwt"
	"github.com/kararnab/iam/token/keys"
)

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

// fakeOIDC authenticates any "sub" param, standing in for an external provider.
type fakeOIDC struct{}

func (fakeOIDC) Name() string { return "oidc" }
func (fakeOIDC) Authenticate(_ context.Context, p map[string]string) (*provider.Identity, error) {
	if p["sub"] == "" {
		return nil, provider.ErrInvalidCredentials
	}
	return &provider.Identity{Provider: "oidc", ProviderID: p["sub"]}, nil
}

type fixture struct {
	svc   *Service
	users *memstore.Users
}

const adminPW = "correct horse battery staple"

func newFixture(t *testing.T) fixture {
	t.Helper()
	ctx := context.Background()
	users := memstore.NewUsers()
	hasher, err := password.NewArgon2id(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pwProv, err := password.NewProvider(users, hasher, password.Policy{})
	if err != nil {
		t.Fatal(err)
	}

	// Seed: subject "s-admin" with login admin@example.com.
	users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{policy.Admin}, Attrs: map[string]string{"org": "acme"}})
	id, err := pwProv.Register(ctx, map[string]string{"username": "Admin@Example.com", "password": adminPW})
	if err != nil {
		t.Fatal(err)
	}
	if err := users.LinkIdentity(ctx, "s-admin", *id); err != nil {
		t.Fatal(err)
	}

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
	svc, err := New(Options{
		Providers:      map[string]provider.AuthProvider{pwProv.Name(): pwProv, "oidc": fakeOIDC{}},
		Users:          users,
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
	return fixture{svc: svc, users: users}
}

func pwLogin(user, pw string) iam.AuthRequest {
	return iam.AuthRequest{Provider: password.ProviderName, Params: map[string]string{"username": user, "password": pw}}
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name    string
		req     iam.AuthRequest
		wantErr error
	}{
		{"password ok, login normalized", pwLogin("  admin@EXAMPLE.com ", adminPW), nil},
		{"wrong password", pwLogin("admin@example.com", "nope"), provider.ErrInvalidCredentials},
		{"unknown login", pwLogin("ghost@example.com", adminPW), provider.ErrInvalidCredentials},
		{"unlinked external identity", iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "g-1"}}, iam.ErrUnknownIdentity},
		{"unknown provider", iam.AuthRequest{Provider: "nope"}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			res, err := f.svc.Authenticate(context.Background(), tt.req)
			if tt.req.Provider == "nope" {
				if err == nil {
					t.Fatal("unknown provider accepted")
				}
				return
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Regression F5: the subject is the canonical ID with roles from the app store.
			if res.Subject.ID != "s-admin" || !slices.Equal(res.Subject.Roles, []string{policy.Admin}) {
				t.Fatalf("subject = %+v", res.Subject)
			}
		})
	}
}

func TestDisabledSubjectCannotLogin(t *testing.T) {
	f := newFixture(t)
	f.users.PutSubject(iam.Subject{ID: "s-admin", Disabled: true})
	if _, err := f.svc.Authenticate(context.Background(), pwLogin("admin@example.com", adminPW)); !errors.Is(err, iam.ErrSubjectDisabled) {
		t.Fatalf("err = %v", err)
	}
}

// Regression F4: refresh used to drop roles and attributes.
func TestRefreshReloadsSubject(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	res, err := f.svc.Authenticate(ctx, pwLogin("admin@example.com", adminPW))
	if err != nil {
		t.Fatal(err)
	}

	at, err := f.svc.Refresh(ctx, res.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := f.svc.VerifyAccessToken(ctx, at)
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID != "s-admin" || !slices.Equal(sub.Roles, []string{policy.Admin}) || sub.Attrs["org"] != "acme" {
		t.Fatalf("refreshed subject = %+v", sub)
	}

	// Role changes take effect at the next refresh.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"reader"}})
	at, _ = f.svc.Refresh(ctx, res.RefreshToken)
	sub, _ = f.svc.VerifyAccessToken(ctx, at)
	if !slices.Equal(sub.Roles, []string{"reader"}) {
		t.Fatalf("roles after change = %v", sub.Roles)
	}

	// Disabling the subject stops refresh and revokes the session.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Disabled: true})
	if _, err := f.svc.Refresh(ctx, res.RefreshToken); !errors.Is(err, iam.ErrSubjectDisabled) {
		t.Fatalf("refresh of disabled subject: %v", err)
	}
	f.users.PutSubject(iam.Subject{ID: "s-admin"})
	if _, err := f.svc.Refresh(ctx, res.RefreshToken); err == nil {
		t.Fatal("session survived a disabled refresh")
	}
}

func TestLinkIdentity(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.users.PutSubject(iam.Subject{ID: "s-other"})
	google := iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "g-1"}}

	if err := f.svc.LinkIdentity(ctx, "s-admin", google); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.LinkIdentity(ctx, "s-admin", google); err != nil {
		t.Fatalf("relinking to the same subject: %v", err)
	}
	if err := f.svc.LinkIdentity(ctx, "s-other", google); !errors.Is(err, iam.ErrIdentityLinked) {
		t.Fatalf("linking to another subject: %v", err)
	}
	if err := f.svc.LinkIdentity(ctx, "s-missing", google); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("linking to a missing subject: %v", err)
	}

	// The linked identity logs in as the same canonical subject.
	res, err := f.svc.Authenticate(ctx, google)
	if err != nil || res.Subject.ID != "s-admin" {
		t.Fatalf("login via linked identity: %v %+v", err, res)
	}
}

func TestRevoke(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	res, err := f.svc.Authenticate(ctx, pwLogin("admin@example.com", adminPW))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(ctx, res.RefreshToken); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx, res.RefreshToken); err == nil {
		t.Fatal("refresh after revoke succeeded")
	}
}
