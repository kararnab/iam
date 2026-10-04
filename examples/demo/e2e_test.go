package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/examples/demo/internal/api"
)

const (
	adminEmail = "admin@example.com"
	adminPW    = "admin-test-password"
)

// newTestServer runs the demo in memory, or on PostgreSQL when
// IAM_TEST_POSTGRES_DSN is set (tables are reset per test).
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newTestServerWith(t, nil)
}

// newTestServerWith is newTestServer with a mailer.
func newTestServerWith(t *testing.T, mailer api.Mailer) *httptest.Server {
	t.Helper()
	dsn := os.Getenv("IAM_TEST_POSTGRES_DSN")
	if dsn != "" {
		resetDatabase(t, dsn)
	}
	a, err := newApp(appConfig{
		Dev:           true,
		SigningKey:    bytes.Repeat([]byte("k"), 32),
		AdminEmail:    adminEmail,
		AdminPassword: adminPW,
		DatabaseURL:   dsn,
		Mailer:        mailer,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(a.handler)
	t.Cleanup(srv.Close)
	return srv
}

func resetDatabase(t *testing.T, dsn string) {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), `DROP TABLE IF EXISTS iam_rotated_tokens, iam_sessions, iam_invites,
		iam_identities, iam_credentials, iam_subjects, iam_one_time_tokens, iam_schema_migrations CASCADE`); err != nil {
		t.Fatal(err)
	}
}

// client is a tiny JSON client that remembers cookies, a CSRF token and a
// bearer token.
type client struct {
	t      *testing.T
	base   string
	http   *http.Client
	csrf   string
	bearer string
}

func newClient(t *testing.T, srv *httptest.Server) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: srv.URL, http: &http.Client{Jar: jar}}
}

func (c *client) do(method, path string, body any, out any) int {
	c.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, r)
	req.Header.Set("Content-Type", "application/json")
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	if c.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			c.t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func (c *client) expect(want int, method, path string, body, out any) {
	c.t.Helper()
	if got := c.do(method, path, body, out); got != want {
		c.t.Fatalf("%s %s = %d, want %d", method, path, got, want)
	}
}

type sessionBody struct {
	Subject struct {
		ID    string   `json:"id"`
		Roles []string `json:"roles"`
	} `json:"subject"`
	Session struct {
		ID string `json:"id"`
	} `json:"session"`
	CSRFToken string `json:"csrf_token"`
}

func login(user, pw string) map[string]any {
	return map[string]any{"provider": "password", "params": map[string]string{"username": user, "password": pw}}
}

// TestCookieFlow: admin invites an editor; the editor signs up with the
// invite, writes a book (CSRF-protected), logs out other sessions and logs
// out.
func TestCookieFlow(t *testing.T) {
	srv := newTestServer(t)

	admin := newClient(t, srv)
	var as sessionBody
	admin.expect(200, "POST", "/api/session/login", login(adminEmail, adminPW), &as)
	if as.CSRFToken == "" || len(as.Subject.Roles) != 1 || as.Subject.Roles[0] != "admin" {
		t.Fatalf("admin session = %+v", as)
	}

	// Unsafe requests need the CSRF token.
	admin.expect(403, "POST", "/api/invites", map[string]any{"roles": []string{"editor"}}, nil)
	admin.csrf = as.CSRFToken
	var inv struct {
		Token string `json:"token"`
	}
	admin.expect(201, "POST", "/api/invites", map[string]any{"roles": []string{"editor"}}, &inv)

	// Sign-up is invite-only.
	editor := newClient(t, srv)
	editor.expect(403, "POST", "/api/session/register", map[string]any{"username": "ed@example.com", "password": "editor password!"}, nil)
	var es sessionBody
	editor.expect(201, "POST", "/api/session/register", map[string]any{"username": "ed@example.com", "password": "editor password!", "invite": inv.Token}, &es)
	if len(es.Subject.Roles) != 1 || es.Subject.Roles[0] != "editor" {
		t.Fatalf("editor roles = %v", es.Subject.Roles)
	}
	editor.expect(403, "POST", "/api/session/register", map[string]any{"username": "eve@example.com", "password": "another password", "invite": inv.Token}, nil)

	// Editor writes a book with the CSRF token; readers' rules are enforced elsewhere.
	editor.expect(403, "POST", "/api/books", map[string]string{"title": "T", "author": "A"}, nil)
	editor.csrf = es.CSRFToken
	editor.expect(201, "POST", "/api/books", map[string]string{"title": "T", "author": "A"}, nil)
	editor.expect(403, "POST", "/admin/keys/rotate", nil, nil)

	// A second session for the editor, then "log out everywhere else".
	other := newClient(t, srv)
	other.expect(200, "POST", "/api/session/login", login("ed@example.com", "editor password!"), nil)
	var sessions []struct {
		ID      string `json:"id"`
		Current bool   `json:"current"`
	}
	editor.expect(200, "GET", "/api/sessions", nil, &sessions)
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	var revoked map[string]int
	editor.expect(200, "POST", "/api/sessions/revoke-others", nil, &revoked)
	if revoked["revoked"] != 1 {
		t.Fatalf("revoked = %v", revoked)
	}
	other.expect(401, "GET", "/api/me", nil, nil)
	editor.expect(200, "GET", "/api/me", nil, nil)

	// Logout ends the session.
	editor.expect(200, "POST", "/api/session/logout", nil, nil)
	editor.expect(401, "GET", "/api/me", nil, nil)
}

// TestBearerFlow: login, use the access token, rotate the refresh token,
// detect reuse, and log out.
func TestBearerFlow(t *testing.T) {
	srv := newTestServer(t)
	c := newClient(t, srv)

	var res struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	c.expect(401, "POST", "/api/login", login(adminEmail, "wrong"), nil)
	c.expect(200, "POST", "/api/login", login(adminEmail, adminPW), &res)

	c.expect(401, "GET", "/api/books", nil, nil)
	c.bearer = res.AccessToken
	c.expect(200, "GET", "/api/books", nil, nil)
	c.expect(201, "POST", "/api/books", map[string]string{"title": "T", "author": "A"}, nil) // no CSRF for bearer
	c.expect(200, "POST", "/admin/keys/rotate", nil, nil)

	var pair struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	c.expect(200, "POST", "/api/refresh", map[string]string{"refresh_token": res.RefreshToken}, &pair)
	if pair.RefreshToken == res.RefreshToken {
		t.Fatal("refresh token did not rotate")
	}
	c.bearer = pair.AccessToken
	c.expect(200, "GET", "/api/me", nil, nil) // signed with the rotated key

	// Reuse of the old refresh token revokes the whole session.
	c.expect(401, "POST", "/api/refresh", map[string]string{"refresh_token": res.RefreshToken}, nil)
	c.expect(401, "POST", "/api/refresh", map[string]string{"refresh_token": pair.RefreshToken}, nil)

	// A fresh login, then logout.
	c.bearer = ""
	c.expect(200, "POST", "/api/login", login(adminEmail, adminPW), &res)
	c.expect(200, "POST", "/api/logout", map[string]string{"refresh_token": res.RefreshToken}, nil)
	c.expect(401, "POST", "/api/refresh", map[string]string{"refresh_token": res.RefreshToken}, nil)
}

func TestLoginThrottling(t *testing.T) {
	srv := newTestServer(t)
	c := newClient(t, srv)
	for range 5 {
		c.expect(401, "POST", "/api/login", login(adminEmail, "wrong"), nil)
	}
	c.expect(429, "POST", "/api/login", login(adminEmail, adminPW), nil)
}

func TestReaderPermissions(t *testing.T) {
	srv := newTestServer(t)
	admin := newClient(t, srv)
	var as sessionBody
	admin.expect(200, "POST", "/api/session/login", login(adminEmail, adminPW), &as)
	admin.csrf = as.CSRFToken
	var inv struct {
		Token string `json:"token"`
	}
	admin.expect(201, "POST", "/api/invites", map[string]any{}, &inv) // defaults to reader
	admin.expect(400, "POST", "/api/invites", map[string]any{"roles": []string{"admin"}}, nil)

	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	reader := newClient(t, srv)
	reader.expect(201, "POST", "/api/register", map[string]any{"username": "rd@example.com", "password": "reader password", "invite": inv.Token}, &tokens)
	reader.bearer = tokens.AccessToken
	reader.expect(200, "GET", "/api/books/1", nil, nil)
	reader.expect(403, "PUT", "/api/books/1", map[string]string{"title": "x", "author": "y"}, nil)
	reader.expect(403, "POST", "/api/invites", map[string]any{}, nil)
}

func TestRequestBodyLimit(t *testing.T) {
	srv := newTestServer(t)
	big := bytes.Repeat([]byte("a"), 2<<20)
	resp, err := http.Post(srv.URL+"/api/login", "application/json", bytes.NewReader(append([]byte(`{"provider":"`), big...)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestLoadConfigFailsClosed(t *testing.T) {
	t.Setenv("IAM_SIGNING_KEY", "")
	t.Setenv("IAM_PASETO_KEY", "")
	if _, err := loadConfig(false); err == nil {
		t.Fatal("started without a signing key")
	}
	t.Setenv("IAM_SIGNING_KEY", "c2hvcnQ=") // "short"
	if _, err := loadConfig(false); err == nil {
		t.Fatal("accepted a short signing key")
	}
	t.Setenv("IAM_SIGNING_KEY", "")
	cfg, err := loadConfig(true)
	if err != nil || len(cfg.SigningKey) < 32 || cfg.AdminEmail != devAdminEmail {
		t.Fatalf("dev config = %+v, %v", cfg, err)
	}
}

// mailbox captures the links the demo would email.
type mailbox struct {
	mu   sync.Mutex
	mail []api.Mail
}

func (m *mailbox) send(_ context.Context, msg api.Mail) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mail = append(m.mail, msg)
}

func (m *mailbox) last(t *testing.T, kind, to string) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := len(m.mail) - 1; i >= 0; i-- {
		if m.mail[i].Kind == kind && m.mail[i].To == to {
			return m.mail[i].Token
		}
	}
	t.Fatalf("no %s mail to %s", kind, to)
	return ""
}

func (m *mailbox) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.mail)
}

// TestPasswordResetFlow: an unknown account gets the same answer and no
// mail; the admin resets their password, which signs them out everywhere.
func TestPasswordResetFlow(t *testing.T) {
	box := &mailbox{}
	srv := newTestServerWith(t, box.send)
	const newPW = "a new admin passphrase"

	signedIn := newClient(t, srv)
	signedIn.expect(200, "POST", "/api/session/login", login(adminEmail, adminPW), nil)

	anon := newClient(t, srv)
	var unknown, known map[string]string
	anon.expect(202, "POST", "/api/password/forgot", map[string]string{"username": "nobody@example.com"}, &unknown)
	if box.count() != 0 {
		t.Fatal("mail sent for an unknown account")
	}
	anon.expect(202, "POST", "/api/password/forgot", map[string]string{"username": adminEmail}, &known)
	if unknown["status"] != known["status"] {
		t.Fatalf("responses differ: %v vs %v", unknown, known)
	}
	tok := box.last(t, "password_reset", adminEmail)

	anon.expect(400, "POST", "/api/password/reset", map[string]string{"token": tok, "password": "short"}, nil)
	anon.expect(204, "POST", "/api/password/reset", map[string]string{"token": tok, "password": newPW}, nil)
	anon.expect(400, "POST", "/api/password/reset", map[string]string{"token": tok, "password": newPW}, nil)

	signedIn.expect(401, "GET", "/api/me", nil, nil)
	anon.expect(401, "POST", "/api/session/login", login(adminEmail, adminPW), nil)
	anon.expect(200, "POST", "/api/session/login", login(adminEmail, newPW), nil)
}

// TestEmailVerificationFlow: a signed-in user verifies an address.
func TestEmailVerificationFlow(t *testing.T) {
	box := &mailbox{}
	srv := newTestServerWith(t, box.send)

	c := newClient(t, srv)
	c.expect(401, "POST", "/api/email/verification", map[string]string{"email": "admin@example.org"}, nil)
	var s sessionBody
	c.expect(200, "POST", "/api/session/login", login(adminEmail, adminPW), &s)
	c.csrf = s.CSRFToken
	c.expect(400, "POST", "/api/email/verification", map[string]string{"email": "not an address"}, nil)
	c.expect(202, "POST", "/api/email/verification", map[string]string{"email": "Admin@Example.org"}, nil)
	tok := box.last(t, "email_verification", "admin@example.org")

	anon := newClient(t, srv)
	var got struct {
		SubjectID string `json:"subject_id"`
		Email     string `json:"email"`
	}
	anon.expect(200, "POST", "/api/email/verify", map[string]string{"token": tok}, &got)
	if got.SubjectID != s.Subject.ID || got.Email != "admin@example.org" {
		t.Fatalf("verified = %+v", got)
	}
	anon.expect(400, "POST", "/api/email/verify", map[string]string{"token": tok}, nil)
}
