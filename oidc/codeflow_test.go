package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// authServer adds an authorization-code grant with PKCE to fakeIssuer.
type authServer struct {
	*fakeIssuer
	t      *testing.T
	mu     sync.Mutex
	grants map[string]grant // code -> grant
	fail   bool             // token endpoint answers 400
}

type grant struct {
	nonce, challenge, redirect string
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	a := &authServer{t: t, grants: map[string]grant{}}
	f := newFakeIssuer(t)
	// Replace the issuer's handler with one that also serves /token.
	inner := f.srv.Config.Handler
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			a.token(w, r)
			return
		}
		inner.ServeHTTP(w, r)
	})
	a.fakeIssuer = f
	return a
}

// authorize plays the user approving the request at authURL, and returns
// the callback query the provider would redirect to.
func (a *authServer) authorize(authURL string) url.Values {
	a.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		a.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" {
		a.t.Fatalf("authorization request lacks PKCE or nonce: %v", q)
	}
	code := "code-" + q.Get("state")[:8]
	a.mu.Lock()
	a.grants[code] = grant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
	a.mu.Unlock()
	return url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {a.srv.URL}}
}

func (a *authServer) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, secret, _ := r.BasicAuth()
	if id == "" {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	a.mu.Lock()
	g, ok := a.grants[r.PostForm.Get("code")]
	delete(a.grants, r.PostForm.Get("code")) // codes are single-use
	a.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if a.fail || !ok || id != "client-1" || secret != "s3cret" ||
		r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("redirect_uri") != g.redirect ||
		base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
		"id_token": a.sign(a.t, a.key, a.claims(func(c map[string]any) { c["nonce"] = g.nonce })),
	})
}

var flowKey = []byte("0123456789abcdef0123456789abcdef")

func newFlow(t *testing.T, a *authServer, mutate func(*CodeFlowConfig)) (*Provider, *CodeFlow) {
	t.Helper()
	p, err := New(context.Background(), Config{Name: "corp", IssuerURL: a.srv.URL, ClientID: "client-1", RequireNonce: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := CodeFlowConfig{
		RedirectURL:  "https://app.example/auth/callback",
		ClientSecret: "s3cret",
		Key:          flowKey,
		AuthParams:   map[string]string{"prompt": "select_account"},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	f, err := NewCodeFlow(p, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p, f
}

// start runs Start and returns the authorization URL and the flow cookie.
func start(t *testing.T, f *CodeFlow, returnTo string) (string, *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	u, err := f.Start(rec, returnTo)
	if err != nil {
		t.Fatal(err)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	return u, cookies[0]
}

func callback(t *testing.T, f *CodeFlow, q url.Values, cookies ...*http.Cookie) (*CallbackResult, *httptest.ResponseRecorder, error) {
	t.Helper()
	r := httptest.NewRequest("GET", "https://app.example/auth/callback?"+q.Encode(), nil)
	for _, c := range cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	res, err := f.Callback(rec, r)
	return res, rec, err
}

func TestCodeFlow(t *testing.T) {
	a := newAuthServer(t)
	p, f := newFlow(t, a, nil)

	authURL, cookie := start(t, f, "/books?shelf=1")
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" ||
		cookie.Name != "__Host-iam-oidc-corp" || cookie.MaxAge != 600 {
		t.Fatalf("cookie = %+v", cookie)
	}
	if strings.Contains(cookie.Value, "select_account") || len(cookie.Value) < 100 {
		t.Fatalf("cookie value does not look encrypted: %q", cookie.Value)
	}
	u, _ := url.Parse(authURL)
	q := u.Query()
	if !strings.HasPrefix(authURL, a.srv.URL+"/auth?") || q.Get("response_type") != "code" || q.Get("client_id") != "client-1" ||
		q.Get("redirect_uri") != "https://app.example/auth/callback" || q.Get("scope") != "openid email profile" ||
		q.Get("prompt") != "select_account" || q.Get("state") == "" {
		t.Fatalf("authorization URL = %s", authURL)
	}

	res, rec, err := callback(t, f, a.authorize(authURL), cookie)
	if err != nil {
		t.Fatal(err)
	}
	if res.ReturnTo != "/books?shelf=1" || res.Params["nonce"] != q.Get("nonce") {
		t.Fatalf("result = %+v", res)
	}
	if cleared := rec.Result().Cookies(); len(cleared) != 1 || cleared[0].MaxAge >= 0 {
		t.Fatalf("callback did not clear the cookie: %v", cleared)
	}
	id, err := p.Authenticate(context.Background(), res.Params)
	if err != nil || id.ProviderID != "user-123" || id.Provider != "corp" {
		t.Fatalf("Authenticate = %+v, %v", id, err)
	}
}

func TestCodeFlowRejects(t *testing.T) {
	a := newAuthServer(t)
	now := time.Now()
	_, f := newFlow(t, a, func(c *CodeFlowConfig) { c.Now = func() time.Time { return now } })
	_, other := newFlow(t, a, func(c *CodeFlowConfig) { c.Key = []byte("another key, also 32 bytes long!") })

	t.Run("no cookie", func(t *testing.T) {
		authURL, _ := start(t, f, "")
		if _, _, err := callback(t, f, a.authorize(authURL)); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("state from another flow", func(t *testing.T) {
		_, cookie := start(t, f, "")
		authURL2, _ := start(t, f, "")
		if _, _, err := callback(t, f, a.authorize(authURL2), cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("tampered cookie", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		b := []byte(cookie.Value)
		b[len(b)/2] ^= 1
		if b[len(b)/2] == cookie.Value[len(b)/2] {
			t.Fatal("not tampered")
		}
		cookie.Value = string(b)
		if _, _, err := callback(t, f, a.authorize(authURL), cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cookie sealed with another key", func(t *testing.T) {
		authURL, cookie := start(t, other, "")
		if _, _, err := callback(t, f, a.authorize(authURL), cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("two cookies", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		if _, _, err := callback(t, f, a.authorize(authURL), cookie, cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		now = now.Add(11 * time.Minute)
		defer func() { now = now.Add(-11 * time.Minute) }()
		if _, _, err := callback(t, f, a.authorize(authURL), cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong issuer parameter", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		q := a.authorize(authURL)
		q.Set("iss", "https://evil.example")
		if _, _, err := callback(t, f, q, cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing code", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		q := a.authorize(authURL)
		q.Del("code")
		if _, _, err := callback(t, f, q, cookie); !errors.Is(err, ErrFlowState) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("user cancelled", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		q := a.authorize(authURL)
		q.Del("code")
		q.Set("error", "access_denied")
		q.Set("error_description", "The user said no")
		_, _, err := callback(t, f, q, cookie)
		var ae *AuthorizationError
		if !errors.As(err, &ae) || ae.Code != "access_denied" || !errors.Is(err, ErrAuthorizationDenied) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("code replayed", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		q := a.authorize(authURL)
		if _, _, err := callback(t, f, q, cookie); err != nil {
			t.Fatal(err)
		}
		if _, _, err := callback(t, f, q, cookie); !errors.Is(err, ErrCodeExchange) {
			t.Fatalf("replay: %v", err)
		}
	})
	t.Run("token endpoint refuses", func(t *testing.T) {
		authURL, cookie := start(t, f, "")
		a.fail = true
		defer func() { a.fail = false }()
		if _, _, err := callback(t, f, a.authorize(authURL), cookie); !errors.Is(err, ErrCodeExchange) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCodeFlowReturnTo(t *testing.T) {
	a := newAuthServer(t)
	_, f := newFlow(t, a, nil)
	for _, bad := range []string{"https://evil.example/", "//evil.example", `/\evil.example`, "evil", "/a\\b", "/a\nb", "javascript:alert(1)"} {
		if _, err := f.Start(httptest.NewRecorder(), bad); !errors.Is(err, ErrInvalidReturnTo) {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
	for _, good := range []string{"", "/", "/a/b?c=d#e"} {
		if _, err := f.Start(httptest.NewRecorder(), good); err != nil {
			t.Errorf("%q rejected: %v", good, err)
		}
	}
}

func TestNewCodeFlowValidates(t *testing.T) {
	a := newAuthServer(t)
	p, err := New(context.Background(), Config{IssuerURL: a.srv.URL, ClientID: "client-1"})
	if err != nil {
		t.Fatal(err)
	}
	good := CodeFlowConfig{RedirectURL: "https://app.example/cb", Key: flowKey}
	cases := map[string]func(*CodeFlowConfig){
		"relative redirect":    func(c *CodeFlowConfig) { c.RedirectURL = "/cb" },
		"http redirect":        func(c *CodeFlowConfig) { c.RedirectURL = "http://app.example/cb" },
		"fragment":             func(c *CodeFlowConfig) { c.RedirectURL = "https://app.example/cb#x" },
		"short key":            func(c *CodeFlowConfig) { c.Key = []byte("short") },
		"long TTL":             func(c *CodeFlowConfig) { c.TTL = 2 * time.Hour },
		"reserved param":       func(c *CodeFlowConfig) { c.AuthParams = map[string]string{"state": "x"} },
		"__Host- and insecure": func(c *CodeFlowConfig) { c.Insecure = true; c.CookieName = "__Host-x" },
	}
	for name, mutate := range cases {
		cfg := good
		mutate(&cfg)
		if _, err := NewCodeFlow(p, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewCodeFlow(nil, good); err == nil {
		t.Error("nil provider accepted")
	}
	insecure := good
	insecure.RedirectURL, insecure.Insecure = "http://localhost:8080/cb", true
	f, err := NewCodeFlow(p, insecure)
	if err != nil {
		t.Fatal(err)
	}
	_, cookie := start(t, f, "")
	if cookie.Secure || cookie.Name != "iam-oidc-oidc" {
		t.Fatalf("insecure cookie = %+v", cookie)
	}
}
