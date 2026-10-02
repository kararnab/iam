package iam_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/policy"
	"github.com/kararnab/iam/v2/provider"
)

// A complete cookie-session lifecycle: invite, sign-up, login, a request,
// authorization, and logout.
func ExampleNew() {
	ctx := context.Background()

	users := memstore.NewUsers()
	hasher, _ := password.NewArgon2id(password.DefaultParams, 0)
	passwords, _ := password.NewProvider(users, hasher, password.DefaultPolicy)
	rbac, _ := policy.NewRBAC(map[string][]policy.Permission{
		"member": {policy.P("read", "note")},
	})

	svc, err := iam.New(iam.Config{
		Providers: []provider.AuthProvider{passwords},
		Users:     users,
		Sessions:  memstore.NewSessions(),
		Policy:    rbac,
		Signup:    iam.SignupConfig{Invites: memstore.NewInvites()},
		Audit:     audit.Func(func(context.Context, audit.Event) error { return nil }), // quiet example
	})
	if err != nil {
		panic(err)
	}

	// An admin invites a member; the invitee signs up with the token.
	inv, _ := svc.CreateInvite(ctx, iam.InviteRequest{Roles: []string{"member"}})
	creds := map[string]string{"username": "ana@example.com", "password": "correct horse battery staple"}
	_, err = svc.SignUp(ctx, iam.SignUpRequest{InviteToken: inv.Token, Provider: password.ProviderName, Params: creds})
	fmt.Println("sign-up:", err)

	// Invites are single-use.
	_, err = svc.SignUp(ctx, iam.SignUpRequest{InviteToken: inv.Token, Provider: password.ProviderName,
		Params: map[string]string{"username": "eve@example.com", "password": "another long password"}})
	fmt.Println("reused invite:", errors.Is(err, iam.ErrInvalidInvite))

	// Login returns a session token for an HttpOnly cookie (see httpauth).
	res, _ := svc.Login(ctx, iam.AuthRequest{Provider: password.ProviderName, Params: creds})
	fmt.Println("mode:", res.Mode, "roles:", res.Subject.Roles)

	// On each request: validate the cookie, then authorize.
	subject, _, _ := svc.ValidateSession(ctx, res.SessionToken)
	read, _ := svc.Authorize(ctx, subject, "read", policy.Resource{Type: "note"})
	del, _ := svc.Authorize(ctx, subject, "delete", policy.Resource{Type: "note"})
	fmt.Println("read:", read.Allowed(), "delete:", del.Allowed())

	_ = svc.Logout(ctx, res.SessionToken)
	_, _, err = svc.ValidateSession(ctx, res.SessionToken)
	fmt.Println("after logout:", errors.Is(err, iam.ErrInvalidSession))

	// Output:
	// sign-up: <nil>
	// reused invite: true
	// mode: cookie roles: [member]
	// read: true delete: false
	// after logout: true
}
