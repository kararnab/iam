package main

import (
	"context"
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
	googleOAuthIssuerUrl = "https://accounts.google.com"
	jwtIssuer            = "auth-monolith"
	jwtAccessTTL         = 15 * time.Minute
	sessionTTL           = 24 * time.Hour
)

func main() {
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
	iamService, userStore, keyProvider, err := buildIAMService(iamMetrics)
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
	secretJWTSigningKey, _ := store.Get(ctx, "SECRET_JWT_SIGNING_KEY")
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
	//or oidcProvider, _ := oidcprov.New(ctx, googleOAuthIssuerUrl, googleOAuthClientID)

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

	pasetoKeyB64 := secretPasetoSigningKey

	if pasetoKeyB64 != "" {
		rawKey, err := base64.StdEncoding.DecodeString(pasetoKeyB64)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("invalid PASETO_KEY: %w", err)
		}
		if len(rawKey) != 32 {
			return nil, nil, nil, fmt.Errorf("PASETO_KEY must be 32 bytes")
		}

		keyProvider = keys.NewMemoryProvider(keys.Key{
			ID:  "paseto-1",
			Key: rawKey,
		})

		issuer, err = paseto.NewIssuer(
			keyProvider.ActiveKey().Key,
			keyProvider.ActiveKey().ID,
			jwtIssuer,
			jwtAccessTTL,
		)
		if err != nil {
			return nil, nil, nil, err
		}

		verifier = &token.MultiVerifier{
			Verifier:    paseto.NewVerifier(jwtIssuer),
			KeyProvider: keyProvider,
		}

	} else {
		// ================================
		// JWT (fallback)
		// ================================
		signingKey := []byte(secretJWTSigningKey)

		keyProvider = keys.NewMemoryProvider(keys.Key{
			ID:  "jwt-1",
			Key: signingKey,
		})

		issuer = jwt.NewIssuer(
			keyProvider.ActiveKey().Key,
			keyProvider.ActiveKey().ID,
			jwtIssuer,
			jwtAccessTTL,
		)

		verifier = &token.MultiVerifier{
			Verifier:    jwt.NewVerifier(jwtIssuer),
			KeyProvider: keyProvider,
		}
	}

	if keyProvider == nil {
		return nil, nil, nil, fmt.Errorf("no signing key configured")
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
