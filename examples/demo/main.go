package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/kararnab/iam/audit"
	"github.com/kararnab/iam/examples/demo/internal/api"
	"github.com/kararnab/iam/examples/demo/internal/books"
	"github.com/kararnab/iam/examples/demo/internal/secrets"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/memstore"
	googleprov "github.com/kararnab/iam/oidc/google"
	"github.com/kararnab/iam/paseto"
	"github.com/kararnab/iam/password"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	"github.com/kararnab/iam/service"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/token"
	"github.com/kararnab/iam/token/jwt"
	"github.com/kararnab/iam/token/keys"

	"github.com/kararnab/iam/metrics"
	prom "github.com/kararnab/iam/prometheus"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/bcrypt"
)

//
// ================================
// CONFIG (MVP CONSTANTS)
// ================================
//
// TODO (prod):
//   - Move to env/config files
//   - Secrets via Vault / SSM / KMS
//

const (
	tokenIssuer   = "iam-demo"
	tokenAudience = "iam-demo-api"
	accessTTL     = 10 * time.Minute
	sessionTTL    = 24 * time.Hour
)

func main() {
	dev := flag.Bool("dev", false, "development mode: generate a random signing key if IAM_SIGNING_KEY is unset")
	flag.Parse()

	// -------------------------------
	// Logger
	// -------------------------------
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	slog.Info("starting application")

	// -------------------------------
	// Metrics
	// -------------------------------
	registry := prom.NewRegistry()
	iamMetrics := prom.NewIAMMetrics(registry)

	// -------------------------------
	// IAM + infra wiring
	// -------------------------------
	deps, err := buildIAMService(iamMetrics, *dev)
	if err != nil {
		slog.Error("failed to start IAM", "error", err)
		os.Exit(1)
	}

	// -------------------------------
	// HTTP API
	// -------------------------------
	authHandlers := api.NewHandlers(deps.iam, deps.users, deps.passwords)
	bookStore := books.NewMemoryStore()
	bookHandlers := api.NewBookHandlers(bookStore)
	keyRotationHandler := api.NewKeyRotationHandler(deps.keys)
	metricsHandler := promhttp.HandlerFor(
		registry,
		promhttp.HandlerOpts{},
	)

	router := api.NewRouter(authHandlers, bookHandlers, keyRotationHandler)

	// Metrics listen on a separate, loopback-only admin address by default.
	adminAddr := os.Getenv("ADMIN_ADDR")
	if adminAddr == "" {
		adminAddr = "127.0.0.1:9090"
	}
	adminMux := http.NewServeMux()
	adminMux.Handle("GET /metrics", metricsHandler)
	go func() {
		slog.Info("admin server running", "addr", adminAddr)
		if err := newServer(adminAddr, adminMux).ListenAndServe(); err != nil {
			slog.Error("admin server failed", "error", err)
		}
	}()

	portAddr := ":" + getPort()
	slog.Info("server running", "addr", portAddr)
	if err := newServer(portAddr, router).ListenAndServe(); err != nil {
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// newServer returns an http.Server with timeouts, so slow clients cannot hold
// connections open indefinitely.
func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

//
// ================================
// IAM WIRING
// ================================
//

// demoDeps is everything main needs from the IAM wiring.
type demoDeps struct {
	iam       iam.Service
	users     *memstore.Users
	passwords *password.Provider
	keys      *keys.MemoryProvider
}

func buildIAMService(
	iamMetrics metrics.IAMMetrics,
	dev bool,
) (*demoDeps, error) {

	ctx := context.Background()

	// Secret Loader
	store := secrets.BuildSecretStore()
	secretUserPassword, _ := store.Get(ctx, "SECRET_USER_PASSWORD")
	secretUserId, _ := store.Get(ctx, "SECRET_USER_ID")
	secretUserName, _ := store.Get(ctx, "SECRET_USERNAME")
	secretSigningKey, _ := store.Get(ctx, "IAM_SIGNING_KEY")
	secretPasetoSigningKey, _ := store.Get(ctx, "SECRET_PASETO_SIGNING_KEY")
	googleOAuthClientID, _ := store.Get(ctx, "GOOGLE_OAUTH_CLIENTID")

	// -------------------------------
	// User store (application-owned)
	// -------------------------------
	userStore := memstore.NewUsers()

	hasher, err := password.NewArgon2id(password.DefaultParams, 0)
	if err != nil {
		return nil, err
	}
	passwordProvider, err := password.NewProvider(userStore, hasher, password.DefaultPolicy)
	if err != nil {
		return nil, err
	}

	// Seed the admin with a legacy bcrypt hash: the first login migrates it
	// to argon2id transparently.
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(secretUserPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	adminLogin := password.NormalizeLogin(secretUserName)
	userStore.PutSubject(iam.Subject{ID: secretUserId, Roles: []string{policy.Admin}})
	if err := userStore.CreateCredential(ctx, adminLogin, string(legacyHash)); err != nil {
		return nil, err
	}
	if err := userStore.LinkIdentity(ctx, secretUserId, provider.Identity{
		Provider: password.ProviderName, ProviderID: adminLogin,
	}); err != nil {
		return nil, err
	}

	// -------------------------------
	// Providers
	// -------------------------------
	googleProvider := googleprov.New(googleOAuthClientID)
	//or oidcProvider, _ := oidcprov.New(ctx, "https://accounts.google.com", googleOAuthClientID)

	providers := map[string]provider.AuthProvider{
		passwordProvider.Name(): passwordProvider,
		googleProvider.Name():   googleProvider,
	}

	// -------------------------------
	// Sessions
	// -------------------------------
	sessionStore := session.NewMemoryStore()
	sessionManager := session.NewManager(
		sessionStore,
		sessionTTL,
	)

	// -------------------------------
	// Tokens + keys
	// -------------------------------
	var (
		issuer      token.Issuer
		verifier    token.Verifier
		keyProvider *keys.MemoryProvider
	)

	if secretPasetoSigningKey != "" {
		rawKey, err := base64.StdEncoding.DecodeString(secretPasetoSigningKey)
		if err != nil {
			return nil, fmt.Errorf("invalid SECRET_PASETO_SIGNING_KEY: %w", err)
		}

		keyProvider = keys.NewMemoryProvider(keys.Key{ID: "paseto-1", Secret: rawKey})

		issuer, err = paseto.NewIssuer(keyProvider, tokenIssuer, accessTTL)
		if err != nil {
			return nil, err
		}
		verifier = paseto.NewVerifier(keyProvider, tokenIssuer)

	} else {
		// ================================
		// JWT (default)
		// ================================
		signingKey, err := loadSigningKey(secretSigningKey, dev)
		if err != nil {
			return nil, err
		}

		keyProvider = keys.NewMemoryProvider(keys.Key{ID: "jwt-1", Alg: keys.HS256, Secret: signingKey})

		cfg := jwt.Config{Issuer: tokenIssuer, Audience: tokenAudience, TTL: accessTTL}
		if issuer, err = jwt.NewIssuer(keyProvider, cfg); err != nil {
			return nil, err
		}
		if verifier, err = jwt.NewVerifier(keyProvider, cfg); err != nil {
			return nil, err
		}
	}

	// -------------------------------
	// IAM service
	// -------------------------------
	iamService, err := service.New(service.Options{
		Providers:      providers,
		Users:          userStore,
		SessionManager: sessionManager,
		SessionStore:   sessionStore,
		TokenIssuer:    issuer,
		TokenVerifier:  verifier,
		PolicyEngine:   &policy.DefaultPolicy{},
		AuditLogger:    audit.NewSlogLogger(nil),
		Metrics:        iamMetrics,
	})
	if err != nil {
		return nil, err
	}

	return &demoDeps{iam: iamService, users: userStore, passwords: passwordProvider, keys: keyProvider}, nil
}

// loadSigningKey decodes IAM_SIGNING_KEY (standard base64, at least 32 bytes).
// Without it the demo refuses to start, unless dev is set, in which case a
// random key is generated (tokens then do not survive a restart).
func loadSigningKey(b64Key string, dev bool) ([]byte, error) {
	if b64Key == "" {
		if !dev {
			return nil, errors.New("IAM_SIGNING_KEY is not set (generate one with: openssl rand -base64 32), or run with -dev")
		}
		slog.Warn("IAM_SIGNING_KEY not set; using a random key (dev mode)")
		key := make([]byte, keys.MinHMACKeySize)
		_, _ = rand.Read(key)
		return key, nil
	}
	key, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("invalid IAM_SIGNING_KEY: %w", err)
	}
	if len(key) < keys.MinHMACKeySize {
		return nil, fmt.Errorf("IAM_SIGNING_KEY must decode to at least %d bytes", keys.MinHMACKeySize)
	}
	return key, nil
}

func getPort() string {
	const defaultPort = 8080

	raw := os.Getenv("PORT")
	if raw == "" {
		return fmt.Sprintf("%d", defaultPort)
	}

	port, err := strconv.Atoi(raw)
	if err != nil {
		slog.Error("invalid PORT (not a number)", "PORT", raw)
		os.Exit(1)
	}

	if port < 1 || port > 65535 {
		slog.Error("invalid PORT (out of range)", "PORT", raw)
		os.Exit(1)
	}

	return raw
}
