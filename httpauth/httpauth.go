// Package httpauth adapts an iam.Service to net/http.
//
// It depends only on the iam.Service interface, so it works the same with
// the in-process service and with a remote one.
//
// Typical use:
//
//	auth, _ := httpauth.New(httpauth.Config{Service: svc})
//	mux.Handle("GET /books", auth.RequirePermission("read", "book", nil)(books))
//	http.ListenAndServe(addr, auth.Protect(mux))
//
// Protect identifies the caller on every request (session cookie or bearer
// token), applies cross-origin protection to unsafe methods, and requires a
// CSRF token for cookie-authenticated unsafe requests. The Require*
// middlewares then reject anonymous or unauthorized callers.
package httpauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/session"
)

// CookieConfig configures the session cookie.
type CookieConfig struct {
	// Name defaults to "__Host-session", or "session" when Insecure is set
	// (the __Host- prefix requires Secure).
	Name string

	// Insecure drops the Secure attribute. Only for local development over
	// plain HTTP; never in production.
	Insecure bool

	// SameSite defaults to http.SameSiteLaxMode. Strict is also supported;
	// None is rejected.
	SameSite http.SameSite
}

// CSRFConfig configures cross-site request forgery protection.
type CSRFConfig struct {
	// Disabled turns off both checks. Only do this if another layer
	// provides CSRF protection.
	Disabled bool

	// Key derives per-session CSRF tokens (HMAC-SHA256). At least 32
	// bytes. If empty, a random key is generated at startup, so tokens do
	// not survive restarts and differ between instances.
	Key []byte

	// TrustedOrigins are additional origins (scheme://host[:port]) allowed
	// to make cross-origin unsafe requests.
	TrustedOrigins []string

	// HeaderName defaults to "X-CSRF-Token"; FieldName (form field) to
	// "csrf_token".
	HeaderName string
	FieldName  string
}

// Config configures the middleware.
type Config struct {
	Service iam.Service

	// Modes the middleware accepts. Default: cookie only.
	Modes []session.Mode

	Cookie CookieConfig
	CSRF   CSRFConfig

	// TrustedProxies are the networks of reverse proxies whose
	// X-Forwarded-For header is believed. Empty: RemoteAddr is used.
	TrustedProxies []netip.Prefix

	// ErrorHandler writes error responses. Default: JSON {"error": "..."}.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, err error)
}

// Middleware is the configured HTTP layer.
type Middleware struct {
	svc            iam.Service
	acceptCookie   bool
	acceptBearer   bool
	cookie         CookieConfig
	csrf           CSRFConfig
	cop            *http.CrossOriginProtection
	trustedProxies []netip.Prefix
	onError        func(http.ResponseWriter, *http.Request, int, error)
}

var (
	// ErrUnauthenticated is passed to the ErrorHandler for anonymous
	// requests to protected handlers.
	ErrUnauthenticated = errors.New("httpauth: authentication required")

	// ErrForbidden is passed to the ErrorHandler for denied requests.
	ErrForbidden = errors.New("httpauth: forbidden")

	// ErrUnavailable is passed to the ErrorHandler, with status 503, when
	// the credential could not be checked because a store failed. It wraps
	// iam.ErrUnavailable. The request is not treated as anonymous: that
	// would make a signed-in user look signed out during an outage.
	ErrUnavailable = fmt.Errorf("httpauth: %w", iam.ErrUnavailable)

	// ErrCSRF is passed to the ErrorHandler when the CSRF token is missing
	// or wrong.
	ErrCSRF = errors.New("httpauth: invalid CSRF token")
)

// New validates the configuration and returns the middleware.
func New(cfg Config) (*Middleware, error) {
	if cfg.Service == nil {
		return nil, errors.New("httpauth: Service is required")
	}
	m := &Middleware{
		svc:            cfg.Service,
		cookie:         cfg.Cookie,
		csrf:           cfg.CSRF,
		trustedProxies: slices.Clone(cfg.TrustedProxies),
		onError:        cfg.ErrorHandler,
	}

	modes := cfg.Modes
	if len(modes) == 0 {
		modes = []session.Mode{session.ModeCookie}
	}
	for _, mode := range modes {
		switch mode {
		case session.ModeCookie:
			m.acceptCookie = true
		case session.ModeBearer:
			m.acceptBearer = true
		default:
			return nil, errors.New("httpauth: invalid mode")
		}
	}

	if m.cookie.Name == "" {
		m.cookie.Name = "__Host-session"
		if m.cookie.Insecure {
			m.cookie.Name = "session"
		}
	}
	if strings.HasPrefix(m.cookie.Name, "__Host-") && m.cookie.Insecure {
		return nil, errors.New("httpauth: __Host- cookies require Secure")
	}
	switch m.cookie.SameSite {
	case 0, http.SameSiteDefaultMode:
		m.cookie.SameSite = http.SameSiteLaxMode
	case http.SameSiteLaxMode, http.SameSiteStrictMode:
	default:
		return nil, errors.New("httpauth: SameSite must be Lax or Strict")
	}

	if m.csrf.HeaderName == "" {
		m.csrf.HeaderName = "X-CSRF-Token"
	}
	if m.csrf.FieldName == "" {
		m.csrf.FieldName = "csrf_token"
	}
	if len(m.csrf.Key) == 0 {
		m.csrf.Key = make([]byte, 32)
		_, _ = rand.Read(m.csrf.Key)
	} else if len(m.csrf.Key) < 32 {
		return nil, errors.New("httpauth: CSRF key must be at least 32 bytes")
	}
	m.csrf.Key = slices.Clone(m.csrf.Key)

	m.cop = http.NewCrossOriginProtection()
	for _, o := range m.csrf.TrustedOrigins {
		if err := m.cop.AddTrustedOrigin(o); err != nil {
			return nil, err
		}
	}

	if m.onError == nil {
		m.onError = writeJSONError
	}
	return m, nil
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

type ctxKey struct{}

type authState struct {
	subject *iam.Subject
	session *iam.SessionInfo
	mode    session.Mode
}

// WithSubject returns a context carrying subject and session, as Protect
// would set them. Intended for tests of handlers.
func WithSubject(ctx context.Context, subject *iam.Subject, sess *iam.SessionInfo) context.Context {
	mode := session.Mode("")
	if sess != nil {
		mode = sess.Mode
	}
	return context.WithValue(ctx, ctxKey{}, &authState{subject: subject, session: sess, mode: mode})
}

func stateFrom(ctx context.Context) *authState {
	st, _ := ctx.Value(ctxKey{}).(*authState)
	if st == nil || st.subject == nil {
		return nil
	}
	return st
}

// SubjectFrom returns the authenticated subject, if any.
func SubjectFrom(ctx context.Context) (*iam.Subject, bool) {
	if st := stateFrom(ctx); st != nil {
		return st.subject, true
	}
	return nil, false
}

// SessionFrom returns the authenticated session, if any.
func SessionFrom(ctx context.Context) (*iam.SessionInfo, bool) {
	if st := stateFrom(ctx); st != nil && st.session != nil {
		return st.session, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------
// Protect: identification, cross-origin protection and CSRF
// ---------------------------------------------------------------------------

func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	return false
}

// Protect wraps the whole handler tree. It:
//
//  1. rejects cross-origin unsafe requests (http.CrossOriginProtection,
//     based on Sec-Fetch-Site / Origin), including unauthenticated ones such
//     as login forms;
//  2. identifies the caller from the session cookie or the Authorization
//     header; invalid credentials make the request anonymous, while a store
//     failure while checking them answers 503 with ErrUnavailable;
//  3. for unsafe methods authenticated by cookie, requires the per-session
//     CSRF token (header or form field).
//
// Bearer-authenticated requests are not subject to CSRF checks: browsers do
// not attach Authorization headers automatically.
func (m *Middleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.csrf.Disabled && !isSafeMethod(r.Method) {
			if err := m.cop.Check(r); err != nil {
				m.onError(w, r, http.StatusForbidden, err)
				return
			}
		}

		st, err := m.identify(r)
		if err != nil {
			m.onError(w, r, http.StatusServiceUnavailable, ErrUnavailable)
			return
		}
		if st != nil && st.mode == session.ModeCookie && !m.csrf.Disabled && !isSafeMethod(r.Method) {
			if !m.validCSRF(r, st.session.ID) {
				m.onError(w, r, http.StatusForbidden, ErrCSRF)
				return
			}
		}
		if st != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, st))
		}
		next.ServeHTTP(w, r)
	})
}

// identify returns the caller's state, or nil for anonymous requests.
// A request presenting both a cookie and a bearer token is rejected as
// anonymous, because it is ambiguous. The error is non-nil only when a
// store failed (iam.ErrUnavailable); invalid credentials are anonymous.
func (m *Middleware) identify(r *http.Request) (*authState, error) {
	bearer, hasBearer := m.bearerToken(r)
	cookie, hasCookie := m.sessionCookie(r)
	if hasBearer && hasCookie {
		return nil, nil
	}

	switch {
	case hasCookie:
		subject, info, err := m.svc.ValidateSession(r.Context(), cookie)
		if err != nil {
			return nil, unavailable(err)
		}
		return &authState{subject: subject, session: info, mode: session.ModeCookie}, nil
	case hasBearer:
		subject, info, err := m.svc.VerifyAccessToken(r.Context(), bearer)
		if err != nil {
			return nil, unavailable(err)
		}
		return &authState{subject: subject, session: info, mode: session.ModeBearer}, nil
	}
	return nil, nil
}

// unavailable returns err if it reports a store failure, and nil for every
// other error (an invalid credential, which makes the request anonymous).
func unavailable(err error) error {
	if errors.Is(err, iam.ErrUnavailable) {
		return err
	}
	return nil
}

func (m *Middleware) bearerToken(r *http.Request) (string, bool) {
	if !m.acceptBearer {
		return "", false
	}
	h := r.Header.Values("Authorization")
	if len(h) != 1 {
		return "", false
	}
	scheme, tok, ok := strings.Cut(h[0], " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || strings.ContainsAny(tok, " \t") {
		return "", false
	}
	return tok, true
}

// sessionCookie returns the session cookie value. More than one cookie with
// the name (for example one injected from a sibling subdomain) is ambiguous
// and ignored.
func (m *Middleware) sessionCookie(r *http.Request) (string, bool) {
	if !m.acceptCookie {
		return "", false
	}
	var found []string
	for _, c := range r.Cookies() {
		if c.Name == m.cookie.Name {
			found = append(found, c.Value)
		}
	}
	if len(found) != 1 || found[0] == "" {
		return "", false
	}
	if _, err := session.HashSecret(found[0]); err != nil {
		return "", false
	}
	return found[0], true
}

// CSRFToken returns the CSRF token for the request's cookie session, or ""
// if the request is not cookie-authenticated. Send it to the page (meta tag,
// JSON) and echo it back in the X-CSRF-Token header or csrf_token field.
func (m *Middleware) CSRFToken(r *http.Request) string {
	st := stateFrom(r.Context())
	if st == nil || st.mode != session.ModeCookie || st.session == nil {
		return ""
	}
	return m.csrfFor(st.session.ID)
}

func (m *Middleware) csrfFor(sessionID string) string {
	mac := hmac.New(sha256.New, m.csrf.Key)
	mac.Write([]byte("iam-csrf-v1:" + sessionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (m *Middleware) validCSRF(r *http.Request, sessionID string) bool {
	got := r.Header.Get(m.csrf.HeaderName)
	if got == "" && isForm(r) {
		got = r.PostFormValue(m.csrf.FieldName)
	}
	want := m.csrfFor(sessionID)
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func isForm(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "multipart/form-data")
}

// ---------------------------------------------------------------------------
// Authorization middlewares
// ---------------------------------------------------------------------------

// RequireAuth rejects anonymous requests with 401. Use inside Protect.
func (m *Middleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stateFrom(r.Context()) == nil {
			m.unauthenticated(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole rejects anonymous requests (401) and subjects without any of
// the roles (403). Prefer RequirePermission, which goes through the policy
// engine and is audited.
func (m *Middleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := stateFrom(r.Context())
			if st == nil {
				m.unauthenticated(w, r)
				return
			}
			for _, role := range roles {
				if slices.Contains(st.subject.Roles, role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			m.onError(w, r, http.StatusForbidden, ErrForbidden)
		})
	}
}

// RequirePermission asks the policy engine whether the caller may perform
// action on resourceType. resource, if non-nil, fills in the resource ID
// and attributes from the request (for example r.PathValue("id")).
func (m *Middleware) RequirePermission(action policy.Action, resourceType string, resource func(*http.Request) policy.Resource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			st := stateFrom(r.Context())
			if st == nil {
				m.unauthenticated(w, r)
				return
			}
			res := policy.Resource{Type: resourceType}
			if resource != nil {
				res = resource(r)
				res.Type = resourceType
			}
			d, err := m.svc.Authorize(r.Context(), st.subject, action, res)
			if err != nil || !d.Allowed() {
				m.onError(w, r, http.StatusForbidden, ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Middleware) unauthenticated(w http.ResponseWriter, r *http.Request) {
	if m.acceptBearer {
		w.Header().Set("WWW-Authenticate", `Bearer`)
	}
	m.onError(w, r, http.StatusUnauthorized, ErrUnauthenticated)
}

// ---------------------------------------------------------------------------
// Cookie sessions
// ---------------------------------------------------------------------------

// StartSession sets the session cookie for a cookie-mode login result and
// returns the CSRF token for the new session. It does nothing for other
// modes.
func (m *Middleware) StartSession(w http.ResponseWriter, res *iam.LoginResult) string {
	if res == nil || res.Mode != session.ModeCookie || res.SessionToken == "" {
		return ""
	}
	//nolint:gosec // G124: HttpOnly and SameSite are fixed; Secure is on unless CookieConfig.Insecure
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie.Name,
		Value:    res.SessionToken,
		Path:     "/",
		Expires:  res.Session.ExpiresAt,
		Secure:   !m.cookie.Insecure,
		HttpOnly: true,
		SameSite: m.cookie.SameSite,
	})
	return m.csrfFor(res.Session.ID)
}

// EndSession logs out the cookie session of r (if any) and clears the
// cookie.
func (m *Middleware) EndSession(w http.ResponseWriter, r *http.Request) error {
	var err error
	if tok, ok := m.sessionCookie(r); ok {
		err = m.svc.Logout(r.Context(), tok)
	}
	//nolint:gosec // G124: same attributes as StartSession; this cookie only clears the session
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie.Name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		Secure:   !m.cookie.Insecure,
		HttpOnly: true,
		SameSite: m.cookie.SameSite,
	})
	return err
}

// ---------------------------------------------------------------------------
// Client information
// ---------------------------------------------------------------------------

// ClientInfo returns the client's IP and user agent for iam requests.
//
// X-Forwarded-For is only used when the direct peer is a trusted proxy;
// the client IP is then the rightmost address not in TrustedProxies.
func (m *Middleware) ClientInfo(r *http.Request) iam.ClientInfo {
	return iam.ClientInfo{IP: m.clientIP(r), UserAgent: r.UserAgent()}
}

func (m *Middleware) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	if !m.trusted(peer) {
		return peer.String()
	}

	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, h := range strings.Split(v, ",") {
			hops = append(hops, strings.TrimSpace(h))
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			break // malformed: stop at the last address we could trust
		}
		addr = addr.Unmap()
		if !m.trusted(addr) {
			return addr.String()
		}
		peer = addr
	}
	return peer.String()
}

func (m *Middleware) trusted(a netip.Addr) bool {
	for _, p := range m.trustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

func writeJSONError(w http.ResponseWriter, _ *http.Request, status int, _ error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": strings.ToLower(http.StatusText(status))})
}
