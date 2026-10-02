package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"

	"github.com/kararnab/iam/examples/demo/internal/api"
	"github.com/kararnab/iam/examples/demo/internal/books"
	"github.com/kararnab/iam/oidc/v2"
	"github.com/kararnab/iam/paseto/v2"
	prom "github.com/kararnab/iam/prometheus/v2"
	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/httpauth"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/ratelimit"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/token"
	"github.com/kararnab/iam/v2/token/jwt"
	"github.com/kararnab/iam/v2/token/keys"
)

const (
	tokenIssuer   = "iam-demo"
	tokenAudience = "iam-demo-api" //nolint:gosec // G101: an audience name, not a credential
	accessTTL     = 10 * time.Minute
)

// appConfig is everything the demo reads from its environment.
type appConfig struct {
	Dev bool // plain-HTTP cookies, random keys allowed, demo admin seeded

	SigningKey []byte // HS256 key for JWT access tokens (>= 32 bytes)
	PasetoKey  []byte // optional: use PASETO instead of JWT (32 bytes)
	CSRFKey    []byte // optional; random if empty

	AdminEmail    string // optional: seed an admin account
	AdminPassword string

	GoogleClientID string // optional: enable Google sign-in
	DatabaseURL    string // optional: PostgreSQL instead of in-memory stores
	OpenSignup     bool   // default is invite-only

	TrustedProxies []string // CIDRs whose X-Forwarded-For is trusted
}

type app struct {
	handler http.Handler // public API
	metrics http.Handler // Prometheus, for the admin listener
	iam     iam.Service
}

func newApp(cfg appConfig) (*app, error) {
	ctx := context.Background()

	// -------------------------------
	// Metrics
	// -------------------------------
	registry := prom.NewRegistry()
	recorder, err := prom.NewRecorder(registry)
	if err != nil {
		return nil, err
	}

	// -------------------------------
	// Users (application-owned) and providers
	// -------------------------------
	st, err := newStores(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	users := st.users
	hasher, err := password.NewArgon2id(password.DefaultParams, 0)
	if err != nil {
		return nil, err
	}
	passwords, err := password.NewProvider(users, hasher, password.DefaultPolicy)
	if err != nil {
		return nil, err
	}
	providers := []provider.AuthProvider{passwords}
	if cfg.GoogleClientID != "" {
		g, err := oidc.NewGoogle(ctx, cfg.GoogleClientID)
		if err != nil {
			return nil, err
		}
		providers = append(providers, g)
	}

	if cfg.AdminEmail != "" {
		if err := seedAdmin(ctx, st, cfg.AdminEmail, cfg.AdminPassword); err != nil {
			return nil, err
		}
	} else {
		slog.Warn("no admin account configured (IAM_ADMIN_EMAIL); nobody can create invites")
	}

	// -------------------------------
	// Access tokens
	// -------------------------------
	issuer, verifier, keyProvider, err := buildTokens(cfg)
	if err != nil {
		return nil, err
	}

	// -------------------------------
	// Policy, sign-up and rate limits
	// -------------------------------
	rbac, err := api.NewPolicy()
	if err != nil {
		return nil, err
	}
	signup := iam.SignupConfig{Policy: invite.InviteOnly, Invites: st.invites}
	if cfg.OpenSignup {
		signup = iam.SignupConfig{Policy: invite.Open, DefaultRoles: []string{api.RoleReader}}
	}
	perLogin, err := ratelimit.NewMemory(ratelimit.Config{Threshold: 5})
	if err != nil {
		return nil, err
	}
	perIP, err := ratelimit.NewMemory(ratelimit.Config{Threshold: 50})
	if err != nil {
		return nil, err
	}

	// -------------------------------
	// IAM service
	// -------------------------------
	svc, err := iam.New(iam.Config{
		Providers:     providers,
		Users:         users,
		Sessions:      st.sessions,
		AllowedModes:  []session.Mode{session.ModeCookie, session.ModeBearer},
		TokenIssuer:   issuer,
		TokenVerifier: verifier,
		Policy:        rbac,
		Signup:        signup,
		RateLimit:     iam.RateLimitConfig{PerLogin: perLogin, PerIP: perIP},
		Metrics:       recorder,
	})
	if err != nil {
		return nil, err
	}

	// -------------------------------
	// HTTP
	// -------------------------------
	proxies, err := parsePrefixes(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	auth, err := httpauth.New(httpauth.Config{
		Service:        svc,
		Modes:          []session.Mode{session.ModeCookie, session.ModeBearer},
		Cookie:         httpauth.CookieConfig{Insecure: cfg.Dev},
		CSRF:           httpauth.CSRFConfig{Key: cfg.CSRFKey},
		TrustedProxies: proxies,
	})
	if err != nil {
		return nil, err
	}

	handler := api.NewRouter(
		api.NewHandlers(svc, auth),
		api.NewBookHandlers(books.NewMemoryStore()),
		api.NewKeyRotationHandler(keyProvider),
	)

	return &app{
		handler: handler,
		metrics: promhttp.HandlerFor(registry, promhttp.HandlerOpts{}),
		iam:     svc,
	}, nil
}

// seedAdmin creates an admin with a legacy bcrypt hash: the first login
// migrates it to argon2id transparently. An existing login is left alone.
func seedAdmin(ctx context.Context, st *stores, email, pw string) error {
	if pw == "" {
		return errors.New("IAM_ADMIN_PASSWORD is required with IAM_ADMIN_EMAIL")
	}
	login := password.NormalizeLogin(email)
	if _, err := st.users.GetCredential(ctx, login); err == nil {
		return nil
	}
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	id := "admin-" + rand.Text()[:8]
	if err := st.putSubject(ctx, iam.Subject{ID: id, Roles: []string{api.RoleAdmin}}); err != nil {
		return err
	}
	if err := st.users.CreateCredential(ctx, login, string(legacyHash)); err != nil {
		return err
	}
	return st.users.LinkIdentity(ctx, id, provider.Identity{Provider: password.ProviderName, ProviderID: login})
}

func buildTokens(cfg appConfig) (token.Issuer, token.Verifier, *keys.MemoryProvider, error) {
	if len(cfg.PasetoKey) > 0 {
		kp := keys.NewMemoryProvider(keys.Key{ID: "paseto-1", Alg: paseto.V4Local, Secret: cfg.PasetoKey})
		pc := paseto.Config{Issuer: tokenIssuer, Audience: tokenAudience, TTL: accessTTL}
		iss, err := paseto.NewIssuer(kp, pc)
		if err != nil {
			return nil, nil, nil, err
		}
		ver, err := paseto.NewVerifier(kp, pc)
		if err != nil {
			return nil, nil, nil, err
		}
		return iss, ver, kp, nil
	}

	if len(cfg.SigningKey) < keys.MinHMACKeySize {
		return nil, nil, nil, fmt.Errorf("signing key must be at least %d bytes", keys.MinHMACKeySize)
	}
	kp := keys.NewMemoryProvider(keys.Key{ID: "jwt-1", Alg: keys.HS256, Secret: cfg.SigningKey})
	jc := jwt.Config{Issuer: tokenIssuer, Audience: tokenAudience, TTL: accessTTL}
	iss, err := jwt.NewIssuer(kp, jc)
	if err != nil {
		return nil, nil, nil, err
	}
	ver, err := jwt.NewVerifier(kp, jc)
	if err != nil {
		return nil, nil, nil, err
	}
	return iss, ver, kp, nil
}
