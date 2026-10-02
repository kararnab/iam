package iam_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/memstore"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/jwt"
	"github.com/kararnab/iam/token/keys"
)

var ctx = context.Background()

// recorder captures audit events.
type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Log(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) has(t audit.EventType) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.ContainsFunc(r.events, func(e audit.Event) bool { return e.Type == t })
}

// fakeOIDC authenticates any "sub" param, standing in for an external provider.
type fakeOIDC struct{}

func (fakeOIDC) Name() string { return "oidc" }
func (fakeOIDC) Authenticate(_ context.Context, p map[string]string) (*provider.Identity, error) {
	if p["sub"] == "" {
		return nil, provider.ErrInvalidCredentials
	}
	return &provider.Identity{Provider: "oidc", ProviderID: p["sub"]}, nil
}

// adminOnly allows everything for "admin" and nothing else (P5 replaces it with RBAC).
type adminOnly struct{ err error }

func (a adminOnly) Evaluate(_ context.Context, s policy.SubjectContext, _ policy.Action, _ policy.Resource) (*policy.Decision, error) {
	if a.err != nil {
		return nil, a.err
	}
	if slices.Contains(s.Roles, "admin") {
		return &policy.Decision{Effect: policy.EffectAllow, Reason: "admin"}, nil
	}
	return &policy.Decision{Effect: policy.EffectDeny, Reason: "not admin"}, nil
}

type fixture struct {
	svc   iam.Service
	users *memstore.Users
	audit *recorder
}

const adminPW = "correct horse battery staple"

func newFixture(t *testing.T, mutate func(*iam.Config)) fixture {
	t.Helper()
	users := memstore.NewUsers()
	hasher, err := password.NewArgon2id(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pwProv, err := password.NewProvider(users, hasher, password.Policy{})
	if err != nil {
		t.Fatal(err)
	}

	users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"admin"}, Attrs: map[string]string{"org": "acme"}})
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

	rec := &recorder{}
	cfg := iam.Config{
		Providers:     []provider.AuthProvider{pwProv, fakeOIDC{}},
		Users:         users,
		Sessions:      memstore.NewSessions(),
		AllowedModes:  []session.Mode{session.ModeCookie, session.ModeBearer},
		TokenIssuer:   issuer,
		TokenVerifier: verifier,
		Policy:        adminOnly{},
		Audit:         rec,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := iam.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{svc: svc, users: users, audit: rec}
}

func pwLogin(user, pw string, mode session.Mode) iam.AuthRequest {
	return iam.AuthRequest{
		Provider: password.ProviderName,
		Params:   map[string]string{"username": user, "password": pw},
		Mode:     mode,
		Client:   iam.ClientInfo{IP: "203.0.113.7", UserAgent: "test"},
	}
}

func TestNewValidatesConfig(t *testing.T) {
	base := func() iam.Config {
		return iam.Config{
			Providers: []provider.AuthProvider{fakeOIDC{}},
			Users:     memstore.NewUsers(),
			Sessions:  memstore.NewSessions(),
			Policy:    adminOnly{},
		}
	}
	tests := []struct {
		name   string
		mutate func(*iam.Config)
		ok     bool
	}{
		{"minimal cookie config", func(*iam.Config) {}, true},
		{"no providers", func(c *iam.Config) { c.Providers = nil }, false},
		{"duplicate provider", func(c *iam.Config) { c.Providers = append(c.Providers, fakeOIDC{}) }, false},
		{"no users", func(c *iam.Config) { c.Users = nil }, false},
		{"no sessions", func(c *iam.Config) { c.Sessions = nil }, false},
		{"no policy (no allow-all default)", func(c *iam.Config) { c.Policy = nil }, false},
		{"bearer without tokens", func(c *iam.Config) { c.AllowedModes = []session.Mode{session.ModeBearer} }, false},
		{"bad mode", func(c *iam.Config) { c.AllowedModes = []session.Mode{"magic"} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base()
			tt.mutate(&cfg)
			if _, err := iam.New(cfg); (err == nil) != tt.ok {
				t.Fatalf("New err = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name    string
		req     iam.AuthRequest
		cookie  bool // only allow cookie mode
		wantErr error
	}{
		{"default mode is the first allowed (cookie)", pwLogin(" admin@EXAMPLE.com ", adminPW, ""), false, nil},
		{"bearer", pwLogin("admin@example.com", adminPW, session.ModeBearer), false, nil},
		{"bearer not allowed", pwLogin("admin@example.com", adminPW, session.ModeBearer), true, iam.ErrModeNotAllowed},
		{"wrong password", pwLogin("admin@example.com", "nope", ""), false, iam.ErrInvalidCredentials},
		{"unknown login", pwLogin("ghost@example.com", adminPW, ""), false, iam.ErrInvalidCredentials},
		{"unlinked external identity", iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "g-1"}}, false, iam.ErrUnknownIdentity},
		{"unknown provider", iam.AuthRequest{Provider: "nope"}, false, iam.ErrUnknownProvider},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, func(c *iam.Config) {
				if tt.cookie {
					c.AllowedModes = []session.Mode{session.ModeCookie}
				}
			})
			res, err := f.svc.Login(ctx, tt.req)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("err = %v, want %v", err, tt.wantErr)
				}
				if !f.audit.has(audit.EventLoginFailure) {
					t.Fatal("login failure not audited")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Regression F5: canonical subject, roles from the app store.
			if res.Subject.ID != "s-admin" || !slices.Equal(res.Subject.Roles, []string{"admin"}) {
				t.Fatalf("subject = %+v", res.Subject)
			}
			if res.Session.ID == "" || res.Session.IP != "203.0.113.7" {
				t.Fatalf("session = %+v", res.Session)
			}
			switch res.Mode {
			case session.ModeCookie:
				if res.SessionToken == "" || res.AccessToken != "" || res.RefreshToken != "" {
					t.Fatalf("cookie result = %+v", res)
				}
			case session.ModeBearer:
				if res.SessionToken != "" || res.AccessToken == "" || res.RefreshToken == "" {
					t.Fatalf("bearer result = %+v", res)
				}
			}
			if !f.audit.has(audit.EventLoginSuccess) {
				t.Fatal("login not audited")
			}
		})
	}
}

func TestCookieSession(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	if err != nil {
		t.Fatal(err)
	}

	sub, info, err := f.svc.ValidateSession(ctx, res.SessionToken)
	if err != nil || sub.ID != "s-admin" || info.ID != res.Session.ID {
		t.Fatalf("validate: %v %+v %+v", err, sub, info)
	}

	// Role changes apply on the next request in cookie mode.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"reader"}})
	sub, _, _ = f.svc.ValidateSession(ctx, res.SessionToken)
	if !slices.Equal(sub.Roles, []string{"reader"}) {
		t.Fatalf("roles = %v", sub.Roles)
	}

	// Rotation invalidates the old token.
	rot, err := f.svc.RotateSession(ctx, res.SessionToken)
	if err != nil || rot.SessionToken == res.SessionToken || rot.Session.ID != res.Session.ID {
		t.Fatalf("rotate: %v", err)
	}
	if _, _, err := f.svc.ValidateSession(ctx, res.SessionToken); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("old token after rotate: %v", err)
	}

	// A refresh token is not a session token and vice versa.
	if _, err := f.svc.Refresh(ctx, rot.SessionToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("session token used as refresh token: %v", err)
	}

	// Disabling the subject ends the session.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Disabled: true})
	if _, _, err := f.svc.ValidateSession(ctx, rot.SessionToken); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("disabled subject: %v", err)
	}
	f.users.PutSubject(iam.Subject{ID: "s-admin"})
	if _, _, err := f.svc.ValidateSession(ctx, rot.SessionToken); err == nil {
		t.Fatal("session survived while the subject was disabled")
	}
}

func TestLogout(t *testing.T) {
	for _, mode := range []session.Mode{session.ModeCookie, session.ModeBearer} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, nil)
			res, _ := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, mode))
			tok := res.SessionToken + res.RefreshToken // exactly one is set
			if err := f.svc.Logout(ctx, tok); err != nil {
				t.Fatal(err)
			}
			if err := f.svc.Logout(ctx, tok); err != nil {
				t.Fatalf("second logout: %v", err)
			}
			if list, _ := f.svc.ListSessions(ctx, "s-admin"); len(list) != 0 {
				t.Fatalf("sessions after logout: %d", len(list))
			}
			if !f.audit.has(audit.EventLogout) {
				t.Fatal("logout not audited")
			}
		})
	}
}

// Regression F4: refresh used to drop roles and attributes.
func TestRefresh(t *testing.T) {
	f := newFixture(t, nil)
	res, err := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	if err != nil {
		t.Fatal(err)
	}

	pair, err := f.svc.Refresh(ctx, res.RefreshToken, iam.ClientInfo{})
	if err != nil {
		t.Fatal(err)
	}
	sub, info, err := f.svc.VerifyAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if sub.ID != "s-admin" || !slices.Equal(sub.Roles, []string{"admin"}) || sub.Attrs["org"] != "acme" || info.ID != res.Session.ID {
		t.Fatalf("refreshed subject = %+v, session = %+v", sub, info)
	}

	// Role changes take effect at the next refresh.
	f.users.PutSubject(iam.Subject{ID: "s-admin", Roles: []string{"reader"}})
	pair, _ = f.svc.Refresh(ctx, pair.RefreshToken, iam.ClientInfo{})
	sub, _, _ = f.svc.VerifyAccessToken(ctx, pair.AccessToken)
	if !slices.Equal(sub.Roles, []string{"reader"}) {
		t.Fatalf("roles after change = %v", sub.Roles)
	}

	// Reusing an old refresh token revokes the whole family.
	if _, err := f.svc.Refresh(ctx, res.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrRefreshReused) {
		t.Fatalf("reuse: %v", err)
	}
	if !f.audit.has(audit.EventRefreshReuse) {
		t.Fatal("reuse not audited")
	}
	if _, err := f.svc.Refresh(ctx, pair.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("latest token after reuse: %v", err)
	}
}

func TestRefreshDisabledSubject(t *testing.T) {
	f := newFixture(t, nil)
	res, _ := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	f.users.PutSubject(iam.Subject{ID: "s-admin", Disabled: true})
	if _, err := f.svc.Refresh(ctx, res.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrSubjectDisabled) {
		t.Fatalf("refresh of disabled subject: %v", err)
	}
	f.users.PutSubject(iam.Subject{ID: "s-admin"})
	if list, _ := f.svc.ListSessions(ctx, "s-admin"); len(list) != 0 {
		t.Fatal("session survived a disabled refresh")
	}
}

func TestVerifySessionOnAccess(t *testing.T) {
	tests := []struct {
		name          string
		checkSession  bool
		validAfterOut bool
	}{
		{"stateless: valid until expiry", false, true},
		{"session-checked: revoked immediately", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, func(c *iam.Config) { c.VerifySessionOnAccess = tt.checkSession })
			res, _ := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
			if _, _, err := f.svc.VerifyAccessToken(ctx, res.AccessToken); err != nil {
				t.Fatal(err)
			}
			if _, err := f.svc.RevokeAllSessions(ctx, "s-admin", ""); err != nil {
				t.Fatal(err)
			}
			_, _, err := f.svc.VerifyAccessToken(ctx, res.AccessToken)
			if (err == nil) != tt.validAfterOut {
				t.Fatalf("after revoke: err = %v", err)
			}
		})
	}
}

func TestVerifyAccessTokenRejectsGarbage(t *testing.T) {
	f := newFixture(t, nil)
	if _, _, err := f.svc.VerifyAccessToken(ctx, "nope"); !errors.Is(err, token.ErrInvalidToken) {
		t.Fatalf("err = %v", err)
	}
	if !f.audit.has(audit.EventTokenVerifyFailure) {
		t.Fatal("verify failure not audited")
	}
}

func TestSessionManagement(t *testing.T) {
	f := newFixture(t, nil)
	f.users.PutSubject(iam.Subject{ID: "s-bob"})
	a, _ := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))
	b, _ := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeBearer))
	c, _ := f.svc.Login(ctx, pwLogin("admin@example.com", adminPW, session.ModeCookie))

	list, err := f.svc.ListSessions(ctx, "s-admin")
	if err != nil || len(list) != 3 {
		t.Fatalf("list = %d, %v", len(list), err)
	}

	if err := f.svc.RevokeSession(ctx, "s-bob", a.Session.ID); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("revoking someone else's session: %v", err)
	}
	if err := f.svc.RevokeSession(ctx, "s-admin", b.Session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Refresh(ctx, b.RefreshToken, iam.ClientInfo{}); !errors.Is(err, iam.ErrInvalidSession) {
		t.Fatalf("revoked session refreshed: %v", err)
	}

	// "Log out everywhere else" keeps the current session.
	n, err := f.svc.RevokeAllSessions(ctx, "s-admin", c.Session.ID)
	if err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v", n, err)
	}
	if _, _, err := f.svc.ValidateSession(ctx, a.SessionToken); err == nil {
		t.Fatal("other session survived")
	}
	if _, _, err := f.svc.ValidateSession(ctx, c.SessionToken); err != nil {
		t.Fatalf("current session revoked: %v", err)
	}
}

func TestAuthorize(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name    string
		subject *iam.Subject
		engine  policy.Engine
		allow   bool
		wantErr error
	}{
		{"admin allowed", &iam.Subject{ID: "a", Roles: []string{"admin"}}, adminOnly{}, true, nil},
		{"reader denied", &iam.Subject{ID: "r", Roles: []string{"reader"}}, adminOnly{}, false, nil},
		{"nil subject denied", nil, adminOnly{}, false, nil},
		{"engine error denies", &iam.Subject{ID: "a", Roles: []string{"admin"}}, adminOnly{err: boom}, false, boom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, func(c *iam.Config) { c.Policy = tt.engine })
			d, err := f.svc.Authorize(ctx, tt.subject, "read", policy.Resource{Type: "book"})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if (d.Effect == policy.EffectAllow) != tt.allow {
				t.Fatalf("decision = %+v", d)
			}
			if !tt.allow && !f.audit.has(audit.EventPolicyDenied) {
				t.Fatal("denial not audited")
			}
		})
	}
}

func TestLinkIdentity(t *testing.T) {
	f := newFixture(t, nil)
	f.users.PutSubject(iam.Subject{ID: "s-other"})
	google := iam.AuthRequest{Provider: "oidc", Params: map[string]string{"sub": "g-1"}}

	tests := []struct {
		name    string
		subject string
		wantErr error
	}{
		{"link", "s-admin", nil},
		{"relink same subject", "s-admin", nil},
		{"identity owned by another subject", "s-other", iam.ErrIdentityLinked},
		{"missing subject", "s-missing", iam.ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.svc.LinkIdentity(ctx, tt.subject, google); !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}

	res, err := f.svc.Login(ctx, google)
	if err != nil || res.Subject.ID != "s-admin" {
		t.Fatalf("login via linked identity: %v", err)
	}
}
