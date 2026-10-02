// Command demo is a books API that uses github.com/kararnab/iam the way any
// application would: cookie sessions for browsers, bearer tokens for API
// clients, invite-only sign-up, RBAC, throttled logins and audit logs.
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
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/kararnab/iam/examples/demo/internal/secrets"
	"github.com/kararnab/iam/token/keys"
)

// Demo-only admin credentials, used with -dev when IAM_ADMIN_EMAIL is unset.
// They are public: never use -dev outside your machine.
const (
	devAdminEmail    = "admin@gmail.com"
	devAdminPassword = "p@$$w0rd1"
)

func main() {
	dev := flag.Bool("dev", false, "development mode: plain-HTTP cookies, random signing key if IAM_SIGNING_KEY is unset, demo admin account")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	if err := run(*dev); err != nil {
		slog.Error("demo failed", "error", err)
		os.Exit(1)
	}
}

func run(dev bool) error {
	cfg, err := loadConfig(dev)
	if err != nil {
		return err
	}
	a, err := newApp(cfg)
	if err != nil {
		return err
	}

	// Metrics listen on a separate, loopback-only admin address by default.
	adminAddr := os.Getenv("ADMIN_ADDR")
	if adminAddr == "" {
		adminAddr = "127.0.0.1:9090"
	}
	adminMux := http.NewServeMux()
	adminMux.Handle("GET /metrics", a.metrics)
	go func() {
		slog.Info("admin server running", "addr", adminAddr)
		if err := newServer(adminAddr, adminMux).ListenAndServe(); err != nil {
			slog.Error("admin server failed", "error", err)
		}
	}()

	port, err := getPort()
	if err != nil {
		return err
	}
	slog.Info("server running", "addr", ":"+port, "dev", dev)
	return newServer(":"+port, a.handler).ListenAndServe()
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

// loadConfig reads the environment (see .env.example). Outside dev mode it
// fails closed: no signing key, no start.
func loadConfig(dev bool) (appConfig, error) {
	ctx := context.Background()
	store := secrets.BuildSecretStore()
	get := func(name string) string {
		v, _ := store.Get(ctx, name)
		return v
	}

	cfg := appConfig{
		Dev:            dev,
		AdminEmail:     get("IAM_ADMIN_EMAIL"),
		AdminPassword:  get("IAM_ADMIN_PASSWORD"),
		GoogleClientID: get("GOOGLE_OAUTH_CLIENTID"),
		OpenSignup:     get("IAM_SIGNUP") == "open",
	}
	if p := get("IAM_TRUSTED_PROXIES"); p != "" {
		cfg.TrustedProxies = strings.Split(p, ",")
	}

	var err error
	if cfg.SigningKey, err = decodeKey("IAM_SIGNING_KEY", get("IAM_SIGNING_KEY"), keys.MinHMACKeySize); err != nil {
		return cfg, err
	}
	if cfg.PasetoKey, err = decodeKey("IAM_PASETO_KEY", get("IAM_PASETO_KEY"), 32); err != nil {
		return cfg, err
	}
	if cfg.CSRFKey, err = decodeKey("IAM_CSRF_KEY", get("IAM_CSRF_KEY"), 32); err != nil {
		return cfg, err
	}

	if len(cfg.SigningKey) == 0 && len(cfg.PasetoKey) == 0 {
		if !dev {
			return cfg, errors.New("IAM_SIGNING_KEY is not set (generate one with: openssl rand -base64 32), or run with -dev")
		}
		slog.Warn("IAM_SIGNING_KEY not set; using a random key (dev mode)")
		cfg.SigningKey = make([]byte, keys.MinHMACKeySize)
		_, _ = rand.Read(cfg.SigningKey)
	}
	if dev && cfg.AdminEmail == "" {
		slog.Warn("dev mode: seeding the public demo admin account", "email", devAdminEmail)
		cfg.AdminEmail, cfg.AdminPassword = devAdminEmail, devAdminPassword
	}
	return cfg, nil
}

// decodeKey decodes an optional standard-base64 key of at least minLen bytes.
func decodeKey(name, b64 string, minLen int) ([]byte, error) {
	if b64 == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", name, err)
	}
	if len(key) < minLen {
		return nil, fmt.Errorf("%s must decode to at least %d bytes", name, minLen)
	}
	return key, nil
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("invalid IAM_TRUSTED_PROXIES entry %q: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func getPort() (string, error) {
	raw := os.Getenv("PORT")
	if raw == "" {
		return "8080", nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid PORT %q", raw)
	}
	return raw, nil
}
