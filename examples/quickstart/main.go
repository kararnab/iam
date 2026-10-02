// Command quickstart is the five-minute integration guide from the README:
// a net/http app with cookie sessions, invite-only sign-up and RBAC, using
// only the core module (standard library + golang.org/x/crypto).
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/httpauth"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
)

func main() {
	ctx := context.Background()

	// 1. Users belong to your application. memstore keeps them in memory;
	//    use pgstore or implement iam.UserStore over your own tables.
	users := memstore.NewUsers()
	hasher, err := password.NewArgon2id(password.DefaultParams, 0)
	if err != nil {
		log.Fatal(err)
	}
	passwords, err := password.NewProvider(users, hasher, password.DefaultPolicy)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Who may do what. Anything not granted is denied.
	rbac, err := policy.NewRBAC(map[string][]policy.Permission{
		"admin":  {policy.P(policy.Wildcard, policy.Wildcard)},
		"member": {policy.P("read", "note")},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 3. The IAM service: cookie sessions (the default mode) and
	//    invite-only sign-up (the default once an invite store is set).
	svc, err := iam.New(iam.Config{
		Providers: []provider.AuthProvider{passwords},
		Users:     users,
		Sessions:  memstore.NewSessions(),
		Policy:    rbac,
		Signup:    iam.SignupConfig{Invites: memstore.NewInvites()},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 4. The HTTP layer: session cookie, CSRF protection, authorization.
	//    Insecure (no Secure flag) only because this example serves plain
	//    HTTP on localhost. Never set it in production.
	auth, err := httpauth.New(httpauth.Config{
		Service: svc,
		Cookie:  httpauth.CookieConfig{Insecure: true},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	type credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Invite   string `json:"invite"`
	}
	// startSession sets the cookie and returns the CSRF token to the page.
	startSession := func(w http.ResponseWriter, res *iam.LoginResult) {
		csrf := auth.StartSession(w, res)
		_ = json.NewEncoder(w).Encode(map[string]any{"subject": res.Subject, "csrf_token": csrf})
	}

	mux.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
		var c credentials
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		res, err := svc.SignUp(r.Context(), iam.SignUpRequest{
			InviteToken: c.Invite,
			Provider:    password.ProviderName,
			Params:      map[string]string{"username": c.Username, "password": c.Password},
			Client:      auth.ClientInfo(r),
		})
		if err != nil {
			http.Error(w, "sign-up failed", http.StatusForbidden)
			return
		}
		startSession(w, res)
	})

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var c credentials
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		res, err := svc.Login(r.Context(), iam.AuthRequest{
			Provider: password.ProviderName,
			Params:   map[string]string{"username": c.Username, "password": c.Password},
			Client:   auth.ClientInfo(r),
		})
		if err != nil {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		startSession(w, res)
	})

	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		_ = auth.EndSession(w, r)
	})

	mux.Handle("GET /notes", auth.RequirePermission("read", "note", nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject, _ := httpauth.SubjectFrom(r.Context())
			_ = json.NewEncoder(w).Encode(map[string]string{"hello": subject.ID})
		})))

	// Hand out the first invite. In a real app an admin creates invites
	// through an endpoint guarded by the policy.
	inv, err := svc.CreateInvite(ctx, iam.InviteRequest{Roles: []string{"member"}})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("invite token: %s", inv.Token)

	// Protect wraps everything: it identifies the caller on each request and
	// applies cross-origin and CSRF protection.
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = "localhost:8080"
	}
	log.Printf("listening on %s", addr) //nolint:gosec // G706: ADDR is set by the operator

	// Timeouts stop slow clients from holding connections open.
	srv := &http.Server{
		Addr:              addr,
		Handler:           auth.Protect(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}
