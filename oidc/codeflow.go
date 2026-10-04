package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	// ErrFlowState is returned by Callback when the flow cookie is missing,
	// expired or tampered with, or does not match the request's state or
	// issuer. Start the sign-in again.
	ErrFlowState = errors.New("oidc: sign-in state is missing, expired or does not match")

	// ErrAuthorizationDenied is wrapped by *AuthorizationError.
	ErrAuthorizationDenied = errors.New("oidc: authorization denied")

	// ErrCodeExchange is returned when the code could not be exchanged for
	// an ID token.
	ErrCodeExchange = errors.New("oidc: code exchange failed")

	// ErrInvalidReturnTo is returned by Start for a return address that is
	// not a local path.
	ErrInvalidReturnTo = errors.New("oidc: returnTo must be a local path")
)

// AuthorizationError is returned by Callback when the identity provider
// redirected back with an error, for example "access_denied" when the user
// canceled. It wraps ErrAuthorizationDenied.
type AuthorizationError struct {
	Code        string // the "error" parameter
	Description string // the "error_description" parameter, if any
}

func (e *AuthorizationError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oidc: authorization failed: %s: %s", e.Code, e.Description)
	}
	return "oidc: authorization failed: " + e.Code
}

func (e *AuthorizationError) Unwrap() error { return ErrAuthorizationDenied }

// CodeFlowConfig configures a CodeFlow.
type CodeFlowConfig struct {
	// RedirectURL is the absolute callback URL registered at the provider.
	RedirectURL string

	// ClientSecret authenticates a confidential client at the token
	// endpoint. Leave it empty for a public client (PKCE only).
	ClientSecret string

	// Scopes are requested in addition to "openid". Default: email, profile.
	Scopes []string

	// Key encrypts and authenticates the flow cookie; at least 32 bytes.
	// Give every instance the same key, so a callback can land on any of
	// them.
	Key []byte

	// CookieName defaults to "__Host-iam-oidc-<provider name>", or
	// "iam-oidc-<provider name>" when Insecure is set.
	CookieName string

	// Insecure drops the cookie's Secure attribute. Only for local
	// development over plain HTTP.
	Insecure bool

	// TTL bounds how long a sign-in may take. Default 10 minutes, max 1 hour.
	TTL time.Duration

	// AuthParams are added to the authorization request, for example
	// {"prompt": "select_account"} or Google's {"hd": "example.com"}. They
	// cannot override the parameters CodeFlow sets itself.
	AuthParams map[string]string

	// HTTPClient is used for the token request. Default http.DefaultClient.
	HTTPClient *http.Client

	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
}

// CodeFlow runs the OpenID Connect authorization-code flow for a Provider:
// Start redirects the browser to the provider, Callback exchanges the code
// for an ID token.
//
// The state, nonce and PKCE verifier live in a short-lived, encrypted,
// HttpOnly cookie, so no server-side store is needed and any instance can
// handle the callback. One flow per provider runs per browser at a time:
// starting another one replaces it.
type CodeFlow struct {
	p        *Provider
	oauth    oauth2.Config
	aead     cipher.AEAD
	cookie   string
	insecure bool
	ttl      time.Duration
	params   map[string]string
	client   *http.Client
	now      func() time.Time
}

// reserved are the authorization parameters CodeFlow sets itself.
var reserved = []string{
	"response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method",
}

// NewCodeFlow returns a code flow for p.
func NewCodeFlow(p *Provider, cfg CodeFlowConfig) (*CodeFlow, error) {
	if p == nil {
		return nil, errors.New("oidc: provider is required")
	}
	if p.endpoint.AuthURL == "" || p.endpoint.TokenURL == "" {
		return nil, errors.New("oidc: the issuer publishes no authorization or token endpoint")
	}
	u, err := url.Parse(cfg.RedirectURL)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" {
		return nil, errors.New("oidc: RedirectURL must be an absolute URL without a fragment")
	}
	if u.Scheme != "https" && !cfg.Insecure {
		return nil, errors.New("oidc: RedirectURL must use https (or set Insecure for local development)")
	}
	if len(cfg.Key) < 32 {
		return nil, errors.New("oidc: Key must be at least 32 bytes")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.TTL < 0 || cfg.TTL > time.Hour {
		return nil, errors.New("oidc: TTL must be between 0 and 1 hour")
	}
	for k := range cfg.AuthParams {
		if slices.Contains(reserved, k) {
			return nil, fmt.Errorf("oidc: AuthParams cannot set %q", k)
		}
	}

	name := cfg.CookieName
	if name == "" {
		name = "iam-oidc-" + p.name
		if !cfg.Insecure {
			name = "__Host-" + name
		}
	}
	if strings.HasPrefix(name, "__Host-") && cfg.Insecure {
		return nil, errors.New("oidc: __Host- cookies require Secure")
	}

	// A key per provider, so one flow's cookie never opens another's.
	mac := hmac.New(sha256.New, cfg.Key)
	mac.Write([]byte("iam-oidc-flow-v1:" + p.name))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	scopes := cfg.Scopes
	if scopes == nil {
		scopes = []string{"email", "profile"}
	}
	scopes = append([]string{gooidc.ScopeOpenID}, slices.DeleteFunc(slices.Clone(scopes), func(s string) bool { return s == gooidc.ScopeOpenID })...)

	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &CodeFlow{
		p: p,
		oauth: oauth2.Config{
			ClientID:     p.clientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     p.endpoint,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		aead:     aead,
		cookie:   name,
		insecure: cfg.Insecure,
		ttl:      cfg.TTL,
		params:   cfg.AuthParams,
		client:   cfg.HTTPClient,
		now:      now,
	}, nil
}

// flowState is what the cookie carries.
type flowState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	ReturnTo string `json:"r"`
	Expires  int64  `json:"e"`
}

// Start begins a sign-in: it sets the flow cookie and returns the
// provider's authorization URL, to redirect the browser to. returnTo is a
// local path ("/settings"; empty means "/") handed back by Callback.
func (f *CodeFlow) Start(w http.ResponseWriter, returnTo string) (string, error) {
	if returnTo == "" {
		returnTo = "/"
	}
	if !localPath(returnTo) {
		return "", ErrInvalidReturnTo
	}
	st := flowState{
		State:    rand.Text(),
		Nonce:    rand.Text(),
		Verifier: oauth2.GenerateVerifier(),
		ReturnTo: returnTo,
		Expires:  f.now().Add(f.ttl).Unix(),
	}
	value, err := f.seal(st)
	if err != nil {
		return "", err
	}
	f.setCookie(w, value, int(f.ttl.Seconds()))

	opts := []oauth2.AuthCodeOption{
		oauth2.S256ChallengeOption(st.Verifier),
		oauth2.SetAuthURLParam("nonce", st.Nonce),
	}
	for k, v := range f.params {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return f.oauth.AuthCodeURL(st.State, opts...), nil
}

// Redirect is Start followed by a 303 redirect to the provider. On error it
// writes nothing and returns the error.
func (f *CodeFlow) Redirect(w http.ResponseWriter, r *http.Request, returnTo string) error {
	u, err := f.Start(w, returnTo)
	if err != nil {
		return err
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
	return nil
}

// CallbackResult is returned by Callback.
type CallbackResult struct {
	// Params are the params for an iam.AuthRequest or iam.SignUpRequest
	// with this provider's Name: "id_token" and "nonce". The nonce comes
	// from the flow cookie, never from the request.
	Params map[string]string

	// ReturnTo is the local path given to Start.
	ReturnTo string
}

// Callback completes a sign-in at RedirectURL. It always clears the flow
// cookie, checks the state (and the "iss" parameter when the provider sends
// one, RFC 9207), and exchanges the code with the PKCE verifier. Pass the
// result to iam.Service.Login (or SignUp, LinkIdentity), which verifies the
// ID token and its nonce.
func (f *CodeFlow) Callback(w http.ResponseWriter, r *http.Request) (*CallbackResult, error) {
	st, ok := f.open(r)
	f.setCookie(w, "", -1)
	if !ok {
		return nil, ErrFlowState
	}

	q := r.URL.Query()
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		return nil, ErrFlowState
	}
	if iss := q.Get("iss"); iss != "" && !slices.Contains(f.p.issuers, iss) {
		return nil, ErrFlowState
	}
	if code := q.Get("error"); code != "" {
		return nil, &AuthorizationError{Code: code, Description: q.Get("error_description")}
	}
	code := q.Get("code")
	if code == "" {
		return nil, ErrFlowState
	}

	ctx := r.Context()
	if f.client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, f.client)
	}
	tok, err := f.oauth.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCodeExchange, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return nil, fmt.Errorf("%w: no id_token in the response", ErrCodeExchange)
	}
	return &CallbackResult{
		Params:   map[string]string{"id_token": raw, "nonce": st.Nonce},
		ReturnTo: st.ReturnTo,
	}, nil
}

func (f *CodeFlow) setCookie(w http.ResponseWriter, value string, maxAge int) {
	//nolint:gosec // G124: HttpOnly and SameSite=Lax are fixed; Secure is on unless Insecure
	http.SetCookie(w, &http.Cookie{
		Name:     f.cookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   !f.insecure,
		HttpOnly: true,
		// Lax: the callback is a top-level GET navigation from the provider.
		SameSite: http.SameSiteLaxMode,
	})
}

func (f *CodeFlow) seal(st flowState) (string, error) {
	plain, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, f.aead.NonceSize())
	_, _ = rand.Read(nonce)
	sealed := f.aead.Seal(nonce, nonce, plain, []byte(f.cookie))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// open returns the flow state from the request's cookie, if exactly one
// valid, unexpired cookie is present.
func (f *CodeFlow) open(r *http.Request) (flowState, bool) {
	var st flowState
	var found []string
	for _, c := range r.Cookies() {
		if c.Name == f.cookie {
			found = append(found, c.Value)
		}
	}
	if len(found) != 1 || len(found[0]) > 4096 {
		return st, false
	}
	sealed, err := base64.RawURLEncoding.DecodeString(found[0])
	if err != nil || len(sealed) < f.aead.NonceSize() {
		return st, false
	}
	n := f.aead.NonceSize()
	plain, err := f.aead.Open(nil, sealed[:n], sealed[n:], []byte(f.cookie))
	if err != nil || json.Unmarshal(plain, &st) != nil {
		return st, false
	}
	if st.State == "" || st.Nonce == "" || st.Verifier == "" || f.now().Unix() >= st.Expires {
		return st, false
	}
	return st, true
}

// localPath reports whether p is a path on this site: it starts with one
// slash, and cannot be read as another host by a browser.
func localPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, `/\`) {
		return false
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == ""
}
