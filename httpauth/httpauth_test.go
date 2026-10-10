package httpauth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/httpauth"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/token/jwt"
	"github.com/kararnab/iam/v2/token/keys"
)

var ctx = context.Background()

const pw = "correct horse battery staple"

type env struct {
	svc  iam.Service
	auth *httpauth.Middleware
	srv  http.Handler
}

func newEnv(t *testing.T, cfg httpauth.Config) env {
	t.Helper()
	users := memstore.NewUsers()
	hasher, _ := password.NewArgon2id(password.Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, 0)
	pwProv, _ := password.NewProvider(users, hasher, password.Policy{})
	for _, u := range []struct{ id, login, role string }{{"s-ed", "editor@example.com", "editor"}, {"s-rd", "reader@example.com", "reader"}} {
		users.PutSubject(iam.Subject{ID: u.id, Roles: []string{u.role}})
		id, err := pwProv.Register(ctx, map[string]string{"username": u.login, "password": pw})
		if err != nil {
			t.Fatal(err)
		}
		_ = users.LinkIdentity(ctx, u.id, *id)
	}
	rbac, _ := policy.NewRBAC(map[string][]policy.Permission{
		"editor": {policy.P("read", "book"), policy.P("write", "book")},
		"reader": {policy.P("read", "book")},
	})
	kp := keys.NewMemoryProvider(keys.Key{ID: "k", Alg: keys.HS256, Secret: []byte("0123456789abcdef0123456789abcdef")})
	jc := jwt.Config{Issuer: "i", Audience: "a"}
	iss, _ := jwt.NewIssuer(kp, jc)
	ver, _ := jwt.NewVerifier(kp, jc)
	svc, err := iam.New(iam.Config{
		Providers:     []provider.AuthProvider{pwProv},
		Users:         users,
		Sessions:      memstore.NewSessions(),
		AllowedModes:  []session.Mode{session.ModeCookie, session.ModeBearer},
		TokenIssuer:   iss,
		TokenVerifier: ver,
		Policy:        rbac,
		Audit:         audit.Func(func(context.Context, audit.Event) error { return nil }),
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Service = svc
	auth, err := httpauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := httpauth.SubjectFrom(r.Context())
		_, _ = io.WriteString(w, "ok:"+s.ID)
	})
	mux := http.NewServeMux()
	mux.Handle("GET /me", auth.RequireAuth(ok))
	mux.Handle("POST /books", auth.RequirePermission("write", "book", nil)(ok))
	mux.Handle("GET /books/{id}", auth.RequirePermission("read", "book", func(r *http.Request) policy.Resource {
		return policy.Resource{ID: r.PathValue("id")}
	})(ok))
	mux.Handle("GET /editors", auth.RequireRole("editor")(ok))
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		res, err := svc.Login(r.Context(), iam.AuthRequest{
			Provider: password.ProviderName,
			Params:   map[string]string{"username": r.FormValue("username"), "password": pw},
			Mode:     session.ModeCookie,
		})
		if err != nil {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, auth.StartSession(w, res))
	})
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		_ = auth.EndSession(w, r)
	})
	return env{svc: svc, auth: auth, srv: auth.Protect(mux)}
}

func (e env) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

// login performs a same-origin cookie login and returns the cookie and CSRF token.
func (e env) login(t *testing.T, user string) (*http.Cookie, string) {
	t.Helper()
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username="+url.QueryEscape(user)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	w := e.do(r)
	if w.Code != 200 {
		t.Fatalf("login: %d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	return cookies[0], w.Body.String()
}

func (e env) bearer(t *testing.T, user string) string {
	t.Helper()
	res, err := e.svc.Login(ctx, iam.AuthRequest{
		Provider: password.ProviderName,
		Params:   map[string]string{"username": user, "password": pw},
		Mode:     session.ModeBearer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return res.AccessToken
}

func TestCookieAttributes(t *testing.T) {
	tests := []struct {
		name     string
		cfg      httpauth.CookieConfig
		wantName string
		secure   bool
		sameSite http.SameSite
	}{
		{"defaults", httpauth.CookieConfig{}, "__Host-session", true, http.SameSiteLaxMode},
		{"insecure dev", httpauth.CookieConfig{Insecure: true}, "session", false, http.SameSiteLaxMode},
		{"strict", httpauth.CookieConfig{SameSite: http.SameSiteStrictMode}, "__Host-session", true, http.SameSiteStrictMode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t, httpauth.Config{Cookie: tt.cfg})
			c, csrf := e.login(t, "editor@example.com")
			if c.Name != tt.wantName || c.Secure != tt.secure || !c.HttpOnly || c.SameSite != tt.sameSite || c.Path != "/" || c.Domain != "" {
				t.Fatalf("cookie = %+v", c)
			}
			if c.Expires.IsZero() || csrf == "" {
				t.Fatal("missing expiry or CSRF token")
			}
		})
	}
}

func TestNewValidates(t *testing.T) {
	e := newEnv(t, httpauth.Config{})
	bad := []httpauth.Config{
		{},
		{Service: e.svc, Cookie: httpauth.CookieConfig{Name: "__Host-x", Insecure: true}},
		{Service: e.svc, Cookie: httpauth.CookieConfig{SameSite: http.SameSiteNoneMode}},
		{Service: e.svc, CSRF: httpauth.CSRFConfig{Key: []byte("short")}},
		{Service: e.svc, Modes: []session.Mode{"magic"}},
		{Service: e.svc, CSRF: httpauth.CSRFConfig{TrustedOrigins: []string{"not a url"}}},
	}
	for i, cfg := range bad {
		if _, err := httpauth.New(cfg); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
}

func TestCookieRequests(t *testing.T) {
	e := newEnv(t, httpauth.Config{Modes: []session.Mode{session.ModeCookie, session.ModeBearer}})
	c, csrf := e.login(t, "editor@example.com")
	_, otherCSRF := e.login(t, "reader@example.com")

	req := func(method, path, body string, mutate func(*http.Request)) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(c)
		if mutate != nil {
			mutate(r)
		}
		return r
	}
	hdr := func(k, v string) func(*http.Request) { return func(r *http.Request) { r.Header.Set(k, v) } }

	tests := []struct {
		name string
		r    *http.Request
		want int
	}{
		{"GET needs no CSRF token", req("GET", "/me", "", nil), 200},
		{"POST without CSRF token", req("POST", "/books", "", nil), 403},
		{"POST with header token", req("POST", "/books", "", hdr("X-CSRF-Token", csrf)), 200},
		{"POST with another session's token", req("POST", "/books", "", hdr("X-CSRF-Token", otherCSRF)), 403},
		{"POST with form token", req("POST", "/books", "csrf_token="+csrf, hdr("Content-Type", "application/x-www-form-urlencoded")), 200},
		{"cross-site POST with token", req("POST", "/books", "", func(r *http.Request) {
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
		}), 403},
		{"cross-origin POST by Origin header", req("POST", "/books", "", func(r *http.Request) {
			r.Header.Set("X-CSRF-Token", csrf)
			r.Header.Set("Origin", "https://evil.example")
		}), 403},
		{"cookie plus bearer is ambiguous", req("GET", "/me", "", hdr("Authorization", "Bearer "+e.bearer(t, "editor@example.com"))), 401},
		{"duplicate session cookies are ignored", req("GET", "/me", "", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}), 401},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if w := e.do(tt.r); w.Code != tt.want {
				t.Fatalf("status = %d, want %d (%s)", w.Code, tt.want, w.Body)
			}
		})
	}
}

func TestBearerRequests(t *testing.T) {
	e := newEnv(t, httpauth.Config{Modes: []session.Mode{session.ModeBearer}})
	editor := e.bearer(t, "editor@example.com")
	reader := e.bearer(t, "reader@example.com")

	tests := []struct {
		name   string
		method string
		path   string
		auth   string
		want   int
	}{
		{"anonymous", "GET", "/me", "", 401},
		{"valid", "GET", "/me", "Bearer " + editor, 200},
		{"lowercase scheme", "GET", "/me", "bearer " + editor, 200},
		{"wrong scheme", "GET", "/me", "Basic " + editor, 401},
		{"garbage token", "GET", "/me", "Bearer nope", 401},
		{"no CSRF needed for bearer POST", "POST", "/books", "Bearer " + editor, 200},
		{"permission denied", "POST", "/books", "Bearer " + reader, 403},
		{"permission with resource ID", "GET", "/books/42", "Bearer " + reader, 200},
		{"role allowed", "GET", "/editors", "Bearer " + editor, 200},
		{"role denied", "GET", "/editors", "Bearer " + reader, 403},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.auth != "" {
				r.Header.Set("Authorization", tt.auth)
			}
			w := e.do(r)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if w.Code == 401 && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing WWW-Authenticate")
			}
		})
	}
}

func TestCookieModeIgnoresBearerByDefault(t *testing.T) {
	e := newEnv(t, httpauth.Config{})
	r := httptest.NewRequest("GET", "/me", nil)
	r.Header.Set("Authorization", "Bearer "+e.bearer(t, "editor@example.com"))
	if w := e.do(r); w.Code != 401 {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestCrossOriginLoginBlocked(t *testing.T) {
	e := newEnv(t, httpauth.Config{CSRF: httpauth.CSRFConfig{TrustedOrigins: []string{"https://app.example"}}})
	tests := []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"cross-site form post", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"trusted origin", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://app.example"}, 200},
		{"same-origin", map[string]string{"Sec-Fetch-Site": "same-origin"}, 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/login", strings.NewReader("username=editor@example.com"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range tt.header {
				r.Header.Set(k, v)
			}
			if w := e.do(r); w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// A bearer-only middleware has no cookie for a cross-site request to ride
// on, so cross-origin clients (SPA, Wasm) are not rejected (#23).
func TestBearerOnlySkipsCrossOriginProtection(t *testing.T) {
	e := newEnv(t, httpauth.Config{Modes: []session.Mode{session.ModeBearer}})
	tok := e.bearer(t, "editor@example.com")
	for _, tt := range []struct {
		name string
		auth string
		want int
	}{
		{"authenticated cross-site write", "Bearer " + tok, 200},
		{"anonymous cross-site write", "", 401},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/books", nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			r.Header.Set("Origin", "https://spa.example")
			if tt.auth != "" {
				r.Header.Set("Authorization", tt.auth)
			}
			if w := e.do(r); w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
	// A cross-site login (anonymous, unsafe) reaches the handler too.
	r := httptest.NewRequest("POST", "/login", strings.NewReader("username=editor@example.com"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := e.do(r); w.Code != 200 {
		t.Fatalf("cross-site login: status = %d", w.Code)
	}
}

// With cookie mode also accepted, the check stays on for every request.
func TestMixedModesKeepCrossOriginProtection(t *testing.T) {
	e := newEnv(t, httpauth.Config{Modes: []session.Mode{session.ModeCookie, session.ModeBearer}})
	r := httptest.NewRequest("POST", "/books", nil)
	r.Header.Set("Sec-Fetch-Site", "cross-site")
	r.Header.Set("Authorization", "Bearer "+e.bearer(t, "editor@example.com"))
	if w := e.do(r); w.Code != 403 {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestEndSession(t *testing.T) {
	e := newEnv(t, httpauth.Config{})
	c, csrf := e.login(t, "editor@example.com")

	r := httptest.NewRequest("POST", "/logout", nil)
	r.AddCookie(c)
	r.Header.Set("X-CSRF-Token", csrf)
	w := e.do(r)
	cleared := w.Result().Cookies()
	if w.Code != 200 || len(cleared) != 1 || cleared[0].MaxAge >= 0 || cleared[0].Value != "" {
		t.Fatalf("logout: %d %v", w.Code, cleared)
	}

	r = httptest.NewRequest("GET", "/me", nil)
	r.AddCookie(c)
	if w := e.do(r); w.Code != 401 {
		t.Fatalf("old cookie after logout: %d", w.Code)
	}
}

func TestContextHelpers(t *testing.T) {
	e := newEnv(t, httpauth.Config{})
	if _, ok := httpauth.SubjectFrom(ctx); ok {
		t.Fatal("subject in empty context")
	}
	c := httpauth.WithSubject(ctx, &iam.Subject{ID: "x"}, &iam.SessionInfo{ID: "s", Mode: session.ModeCookie})
	s, ok := httpauth.SubjectFrom(c)
	sess, ok2 := httpauth.SessionFrom(c)
	if !ok || !ok2 || s.ID != "x" || sess.ID != "s" {
		t.Fatal("WithSubject round trip failed")
	}
	r := httptest.NewRequest("GET", "/", nil).WithContext(c)
	if e.auth.CSRFToken(r) == "" {
		t.Fatal("no CSRF token for a cookie session")
	}
}

func TestClientInfo(t *testing.T) {
	e := newEnv(t, httpauth.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	tests := []struct {
		name   string
		remote string
		xff    []string
		want   string
	}{
		{"direct client", "203.0.113.5:1234", nil, "203.0.113.5"},
		{"untrusted peer's XFF ignored", "203.0.113.5:1234", []string{"1.2.3.4"}, "203.0.113.5"},
		{"trusted proxy", "10.0.0.2:1234", []string{"198.51.100.7"}, "198.51.100.7"},
		{"spoofed left entries ignored", "10.0.0.2:1234", []string{"6.6.6.6, 198.51.100.7, 10.0.0.9"}, "198.51.100.7"},
		{"multiple headers", "10.0.0.2:1234", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"malformed hop stops the walk", "10.0.0.2:1234", []string{"198.51.100.7, garbage"}, "10.0.0.2"},
		{"only proxies", "10.0.0.2:1234", []string{"10.0.0.3"}, "10.0.0.3"},
		{"ipv4-mapped ipv6", "[::ffff:203.0.113.5]:1234", nil, "203.0.113.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, v := range tt.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := e.auth.ClientInfo(r).IP; got != tt.want {
				t.Fatalf("IP = %q, want %q", got, tt.want)
			}
		})
	}
}

func FuzzSessionCookie(f *testing.F) {
	secret, _ := session.NewSecret()
	f.Add("__Host-session=" + secret)
	f.Add("__Host-session=" + secret + "; __Host-session=" + secret)
	f.Add("__Host-session=\"" + secret + "\"")
	f.Add("a=b; __Host-session=%00")
	f.Add("")

	// A service whose ValidateSession records what reaches it.
	seen := make(chan string, 1)
	svc := validateSpy{seen: seen}
	auth, err := httpauth.New(httpauth.Config{Service: svc})
	if err != nil {
		f.Fatal(err)
	}
	h := auth.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	f.Fuzz(func(t *testing.T, cookieHeader string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Cookie", cookieHeader)
		h.ServeHTTP(httptest.NewRecorder(), r)
		select {
		case v := <-seen:
			// Only canonical secrets may reach the service.
			if _, err := session.HashSecret(v); err != nil {
				t.Fatalf("non-canonical cookie value reached the service: %q", v)
			}
		default:
		}
	})
}

type validateSpy struct {
	iam.Service
	seen chan string
}

func (v validateSpy) ValidateSession(_ context.Context, tok string) (*iam.Subject, *iam.SessionInfo, error) {
	select {
	case v.seen <- tok:
	default:
	}
	return nil, nil, iam.ErrInvalidSession
}

// unavailableSvc fails every credential check with a store error.
type unavailableSvc struct{ iam.Service }

func (unavailableSvc) ValidateSession(context.Context, string) (*iam.Subject, *iam.SessionInfo, error) {
	return nil, nil, fmt.Errorf("%w: connection refused", iam.ErrUnavailable)
}

func (unavailableSvc) VerifyAccessToken(context.Context, string) (*iam.Subject, *iam.SessionInfo, error) {
	return nil, nil, fmt.Errorf("%w: connection refused", iam.ErrUnavailable)
}

func TestStoreFailureIsServiceUnavailable(t *testing.T) {
	var gotErr error
	auth, err := httpauth.New(httpauth.Config{
		Service: unavailableSvc{},
		Modes:   []session.Mode{session.ModeCookie, session.ModeBearer},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, status int, err error) {
			gotErr = err
			w.WriteHeader(status)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reached := false
	h := auth.Protect(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))

	valid, _ := session.NewSecret()
	tests := []struct {
		name   string
		header string
		value  string
		want   int
	}{
		{"cookie", "Cookie", "__Host-session=" + valid, http.StatusServiceUnavailable},
		{"bearer", "Authorization", "Bearer abc.def.ghi", http.StatusServiceUnavailable},
		{"anonymous", "", "", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reached, gotErr = false, nil
			r := httptest.NewRequest("GET", "/", nil)
			if tt.header != "" {
				r.Header.Set(tt.header, tt.value)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d", w.Code, tt.want)
			}
			if tt.want == http.StatusServiceUnavailable {
				if reached {
					t.Fatal("handler ran as anonymous during a store failure")
				}
				if !errors.Is(gotErr, httpauth.ErrUnavailable) || !errors.Is(gotErr, iam.ErrUnavailable) {
					t.Fatalf("error handler got %v", gotErr)
				}
			}
		})
	}
}

func TestRequireMFA(t *testing.T) {
	e := newEnv(t, httpauth.Config{})
	h := e.auth.RequireMFA(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	serve := func(c context.Context) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil).WithContext(c))
		return w.Code
	}
	subject := &iam.Subject{ID: "x"}
	if code := serve(ctx); code != 401 {
		t.Fatalf("anonymous = %d", code)
	}
	if code := serve(httpauth.WithSubject(ctx, subject, &iam.SessionInfo{ID: "s", Mode: session.ModeCookie})); code != 403 {
		t.Fatalf("password-only session = %d", code)
	}
	if code := serve(httpauth.WithSubject(ctx, subject, nil)); code != 403 {
		t.Fatalf("no session info = %d", code)
	}
	if code := serve(httpauth.WithSubject(ctx, subject, &iam.SessionInfo{ID: "s", Mode: session.ModeCookie, MFA: true})); code != 204 {
		t.Fatalf("MFA session = %d", code)
	}
}
