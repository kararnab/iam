package jwt

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/kararnab/iam/v2/token/keys"
)

// JWK is a public JSON Web Key (RFC 7517) for an Ed25519 key (RFC 8037).
type JWK struct {
	Kty string `json:"kty"`           // "OKP"
	Crv string `json:"crv"`           // "Ed25519"
	X   string `json:"x"`             // base64url public key
	Kid string `json:"kid"`           // key ID, as in the token header
	Alg string `json:"alg,omitempty"` // "EdDSA"
	Use string `json:"use,omitempty"` // "sig"
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWKS returns the public keys of kp's EdDSA verification keys, active
// key first. HS256 secrets and private keys are never included.
func PublicJWKS(kp keys.Provider) JWKS {
	set := JWKS{Keys: []JWK{}}
	for _, k := range kp.VerificationKeys() {
		if k.Alg != keys.EdDSA || k.ID == "" || len(k.PublicKey) != ed25519.PublicKeySize {
			continue
		}
		set.Keys = append(set.Keys, JWK{
			Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(k.PublicKey),
			Kid: k.ID, Alg: string(keys.EdDSA), Use: "sig",
		})
	}
	return set
}

// JWKSHandler serves PublicJWKS(kp) as application/jwk-set+json, for other
// services to verify access tokens without being able to mint them. The
// set is built on every request, so rotation shows up at once; maxAge sets
// Cache-Control (zero means 5 minutes). Keep a rotated-out key until every
// verifier's cache has seen the new one: prune after at least
// maxAge + the access-token TTL.
func JWKSHandler(kp keys.Provider, maxAge time.Duration) http.Handler {
	if maxAge <= 0 {
		maxAge = 5 * time.Minute
	}
	cache := "public, max-age=" + strconv.Itoa(int(maxAge.Seconds()))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := json.Marshal(PublicJWKS(kp))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", cache)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(body)
	})
}

// RemoteKeysConfig configures RemoteKeys.
type RemoteKeysConfig struct {
	// HTTPClient fetches the set. Default: a client with a 10-second timeout.
	HTTPClient *http.Client

	// RefreshInterval is how old the cached set may get before it is
	// fetched again in the background. Default 15 minutes.
	RefreshInterval time.Duration

	// MinRefreshInterval limits fetches caused by unknown key IDs, so
	// tokens with made-up IDs cannot make the verifier hammer the issuer.
	// Default 1 minute.
	MinRefreshInterval time.Duration

	// AllowHTTP permits a plain-HTTP URL. Only for tests and local
	// development: keys fetched over HTTP can be replaced in transit.
	AllowHTTP bool
}

// maxJWKSSize bounds a fetched key set.
const maxJWKSSize = 64 << 10

// RemoteKeys is a verification-only keys.Provider backed by a remote JWKS,
// typically another service's JWKSHandler. Pass it to NewVerifier.
//
// It accepts only Ed25519 keys (kty OKP, alg EdDSA or absent, use sig or
// absent); every key stays pinned to EdDSA. ActiveKey returns the zero Key,
// so RemoteKeys cannot be used to issue tokens. A token with an unknown key
// ID triggers a fetch, at most once per MinRefreshInterval; the cached set
// is also refreshed in the background once it is older than
// RefreshInterval. A failed fetch keeps the previous set.
type RemoteKeys struct {
	url    string
	client *http.Client
	every  time.Duration
	min    time.Duration

	mu        sync.RWMutex
	keys      []keys.Key
	fetchedAt time.Time // last successful fetch
	triedAt   time.Time // last attempt
	fetching  bool
}

var (
	_ keys.Provider = (*RemoteKeys)(nil)
	_ keys.Finder   = (*RemoteKeys)(nil)
)

// NewRemoteKeys fetches the key set at jwksURL once, and fails if that
// fetch fails, so a misconfigured URL is noticed at start-up.
func NewRemoteKeys(ctx context.Context, jwksURL string, cfg RemoteKeysConfig) (*RemoteKeys, error) {
	u, err := url.Parse(jwksURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !cfg.AllowHTTP)) {
		return nil, errors.New("jwt: the JWKS URL must be an absolute https URL")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 15 * time.Minute
	}
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = time.Minute
	}
	r := &RemoteKeys{url: jwksURL, client: cfg.HTTPClient, every: cfg.RefreshInterval, min: cfg.MinRefreshInterval}
	if err := r.Refresh(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

// ActiveKey implements keys.Provider. It returns the zero Key: remote keys
// verify, they never sign.
func (r *RemoteKeys) ActiveKey() keys.Key { return keys.Key{} }

// VerificationKeys implements keys.Provider.
func (r *RemoteKeys) VerificationKeys() []keys.Key {
	r.mu.RLock()
	out := append([]keys.Key(nil), r.keys...)
	stale := time.Since(r.fetchedAt) > r.every
	r.mu.RUnlock()
	if stale {
		r.refreshInBackground()
	}
	return out
}

// FindKey implements keys.Finder: an unknown key ID causes a fetch (rate
// limited), since the issuer may have rotated.
func (r *RemoteKeys) FindKey(id string) (keys.Key, bool) {
	for _, k := range r.VerificationKeys() {
		if k.ID == id {
			return k, true
		}
	}
	r.mu.RLock()
	recent := time.Since(r.triedAt) < r.min
	r.mu.RUnlock()
	if recent || id == "" {
		return keys.Key{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = r.Refresh(ctx)
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, k := range r.keys {
		if k.ID == id {
			return k, true
		}
	}
	return keys.Key{}, false
}

func (r *RemoteKeys) refreshInBackground() {
	r.mu.Lock()
	if r.fetching || time.Since(r.triedAt) < r.min {
		r.mu.Unlock()
		return
	}
	r.fetching = true
	r.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = r.Refresh(ctx)
		r.mu.Lock()
		r.fetching = false
		r.mu.Unlock()
	}()
}

// Refresh fetches the key set now. On failure the previous set is kept.
func (r *RemoteKeys) Refresh(ctx context.Context) error {
	r.mu.Lock()
	r.triedAt = time.Now()
	r.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwt: fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwt: fetch JWKS: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSSize+1))
	if err != nil {
		return fmt.Errorf("jwt: fetch JWKS: %w", err)
	}
	if len(body) > maxJWKSSize {
		return errors.New("jwt: JWKS too large")
	}
	parsed, err := parseJWKS(body)
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.keys, r.fetchedAt = parsed, time.Now()
	r.mu.Unlock()
	return nil
}

// parseJWKS keeps the usable Ed25519 signing keys of a set and ignores the
// rest (other key types are not an error: a set may serve several
// algorithms).
func parseJWKS(body []byte) ([]keys.Key, error) {
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwt: bad JWKS: %w", err)
	}
	var out []keys.Key
	seen := map[string]bool{}
	for _, j := range set.Keys {
		if j.Kty != "OKP" || j.Crv != "Ed25519" || j.Kid == "" ||
			(j.Alg != "" && j.Alg != string(keys.EdDSA)) || (j.Use != "" && j.Use != "sig") {
			continue
		}
		pub, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil || len(pub) != ed25519.PublicKeySize || seen[j.Kid] {
			continue
		}
		seen[j.Kid] = true
		out = append(out, keys.Key{ID: j.Kid, Alg: keys.EdDSA, PublicKey: ed25519.PublicKey(pub)})
	}
	if len(out) == 0 {
		return nil, errors.New("jwt: JWKS has no usable Ed25519 keys")
	}
	return out, nil
}
