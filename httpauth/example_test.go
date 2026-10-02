package httpauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/httpauth"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
)

func ExampleMiddleware_Protect() {
	ctx := context.Background()
	users := memstore.NewUsers()
	hasher, _ := password.NewArgon2id(password.DefaultParams, 0)
	passwords, _ := password.NewProvider(users, hasher, password.DefaultPolicy)
	rbac, _ := policy.NewRBAC(map[string][]policy.Permission{"member": {policy.P("read", "note")}})
	svc, _ := iam.New(iam.Config{
		Providers: []provider.AuthProvider{passwords},
		Users:     users,
		Sessions:  memstore.NewSessions(),
		Policy:    rbac,
		Audit:     audit.Func(func(context.Context, audit.Event) error { return nil }),
	})

	// Seed one member (normally done by sign-up).
	users.PutSubject(iam.Subject{ID: "ana", Roles: []string{"member"}})
	id, _ := passwords.Register(ctx, map[string]string{"username": "ana@example.com", "password": "correct horse battery staple"})
	_ = users.LinkIdentity(ctx, "ana", *id)

	auth, _ := httpauth.New(httpauth.Config{Service: svc})
	mux := http.NewServeMux()
	mux.Handle("GET /notes", auth.RequirePermission("read", "note", nil)(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, _ := httpauth.SubjectFrom(r.Context())
			fmt.Fprint(w, "notes for ", s.ID)
		})))
	handler := auth.Protect(mux)

	// Anonymous request.
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/notes", nil))
	fmt.Println(w.Code)

	// Log in; StartSession sets the __Host-session cookie.
	res, _ := svc.Login(ctx, iam.AuthRequest{Provider: password.ProviderName,
		Params: map[string]string{"username": "ana@example.com", "password": "correct horse battery staple"}})
	login := httptest.NewRecorder()
	auth.StartSession(login, res)
	cookie := login.Result().Cookies()[0]
	fmt.Println(cookie.Name, cookie.HttpOnly, cookie.Secure, cookie.SameSite == http.SameSiteLaxMode)

	r := httptest.NewRequest("GET", "/notes", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	fmt.Println(w.Code, w.Body.String())
	// Output:
	// 401
	// __Host-session true true true
	// 200 notes for ana
}
