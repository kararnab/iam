package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"encoding/base64"
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
	"github.com/kararnab/iam/examples/demo/internal/users"

	"github.com/kararnab/iam"
	googleprov "github.com/kararnab/iam/oidc/google"
	"github.com/kararnab/iam/paseto"
	"github.com/kararnab/iam/policy"
	"github.com/kararnab/iam/provider"
	internalprov "github.com/kararnab/iam/provider/inhouse"
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
	iamService, userStore, keyProvider, err := buildIAMService(iamMetrics, *dev)
	if err != nil {
		slog.Error("failed to start IAM", "error", err)
		os.Exit(1)
	}

	// -------------------------------
	// HTTP API
	// -------------------------------
	authHandlers := api.NewHandlers(iamService, userStore)
	bookStore := books.NewMemoryStore()
	bookHandlers := api.NewBookHandlers(bookStore)
	keyRotationHandler := api.NewKeyRotationHandler(keyProvider)
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

func buildIAMService(
	iamMetrics metrics.IAMMetrics,
	dev bool,
) (
	iam.Service,
	internalprov.UserStore,
	*keys.MemoryProvider,
	error,
) {

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
	userStore := users.NewMemoryUserStore()

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(secretUserPassword),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := userStore.Create(ctx, &internalprov.User{
		ID:           secretUserId,
		Email:        secretUserName,
		PasswordHash: string(hash),
		Roles:        []string{policy.Admin},
	}); err != nil {
		return nil, nil, nil, err
	}

	// -------------------------------
	// Providers
	// -------------------------------
	internalProvider := internalprov.New(userStore)
	googleProvider := googleprov.New(googleOAuthClientID)
	//or oidcProvider, _ := oidcprov.New(ctx, "https://accounts.google.com", googleOAuthClientID)

	providers := map[string]provider.AuthProvider{
		internalProvider.Name(): internalProvider,
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
			return nil, nil, nil, fmt.Errorf("invalid SECRET_PASETO_SIGNING_KEY: %w", err)
		}

		keyProvider = keys.NewMemoryProvider(keys.Key{ID: "paseto-1", Secret: rawKey})

		issuer, err = paseto.NewIssuer(keyProvider, tokenIssuer, accessTTL)
		if err != nil {
			return nil, nil, nil, err
		}
		verifier = paseto.NewVerifier(keyProvider, tokenIssuer)

	} else {
		// ================================
		// JWT (default)
		// ================================
		signingKey, err := loadSigningKey(secretSigningKey, dev)
		if err != nil {
			return nil, nil, nil, err
		}

		keyProvider = keys.NewMemoryProvider(keys.Key{ID: "jwt-1", Alg: keys.HS256, Secret: signingKey})

		cfg := jwt.Config{Issuer: tokenIssuer, Audience: tokenAudience, TTL: accessTTL}
		if issuer, err = jwt.NewIssuer(keyProvider, cfg); err != nil {
			return nil, nil, nil, err
		}
		if verifier, err = jwt.NewVerifier(keyProvider, cfg); err != nil {
			return nil, nil, nil, err
		}
	}

	// -------------------------------
	// IAM service
	// -------------------------------
	iamService, err := service.New(service.Options{
		Providers:      providers,
		SessionManager: sessionManager,
		SessionStore:   sessionStore,
		TokenIssuer:    issuer,
		TokenVerifier:  verifier,
		PolicyEngine:   &policy.DefaultPolicy{},
		AuditLogger:    audit.NewSlogLogger(nil),
		Metrics:        iamMetrics,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return iamService, userStore, keyProvider, nil
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
