# Identity providers

A provider proves who someone is. It does not create sessions, issue tokens
or know about roles.

```go
type AuthProvider interface {
    Name() string
    Authenticate(ctx context.Context, params map[string]string) (*provider.Identity, error)
}

type Identity struct {
    Provider      string // your provider's Name()
    ProviderID    string // stable ID at that provider ("sub", normalized login)
    Email         string
    EmailVerified bool   // only true if the provider asserts it
    DisplayName   string
    Attrs         map[string]string
}
```

IAM maps `(Provider, ProviderID)` to your canonical subject through
`iam.IdentityStore`. A valid identity that is not linked to a subject is
rejected with `iam.ErrUnknownIdentity`, unless it is used in `SignUp`.

## Built-in providers

| Provider | Package | Params |
|---|---|---|
| Username and password | `password.NewProvider` (core) | `username`, `password` |
| Any OpenID Connect issuer | `oidc.New` (module `iam/oidc`) | `id_token`, optional `nonce` |
| Google | `oidc.NewGoogle` | `id_token`, optional `nonce` |
| Passkeys and security keys (WebAuthn) | `webauthn.New` (module `iam/webauthn`, [docs](passkeys.md)) | `state`, `response` |

### Password

```go
hasher, _ := password.NewArgon2id(password.DefaultParams, 0)
p, _ := password.NewProvider(credentialStore, hasher, password.DefaultPolicy)
```

- New hashes use argon2id (`m=19 MiB, t=2, p=1` by default, in PHC format).
  `NewArgon2id`'s second argument bounds concurrent hashing.
- Existing bcrypt hashes verify, and are upgraded to argon2id after the next
  successful login. Raising `Params` upgrades argon2id hashes the same way.
- Logins are trimmed and lower-cased (`password.NormalizeLogin`).
- An unknown login still costs one hash verification, so response time does
  not reveal which logins exist.
- `password.Policy` sets length rules: at least 12 characters, at most 1024
  bytes by default.
- The provider implements `provider.Registrar`, which is what lets
  `Service.SignUp` create credentials, and `provider.PasswordSetter`, which
  lets [password reset](recovery.md) replace them.

Wrong passwords return errors that wrap `provider.ErrInvalidCredentials`
(also exported as `iam.ErrInvalidCredentials`). Only those errors count
towards login throttling.

### OIDC and Google

```go
g, err := oidc.NewGoogle(ctx, googleClientID)
corp, err := oidc.New(ctx, oidc.Config{
    Name:      "corp",                        // stays stable once identities are linked
    IssuerURL: "https://login.example.com/realms/main",
    ClientID:  "my-app",
    RequireNonce: true,
})
```

`New` fetches the issuer's discovery document; pass a long-lived context.
The provider verifies the signature, issuer, audience (your client ID),
expiry and, when given, the nonce.

The **nonce must come from your server**: generate it when you start the
sign-in, keep it in server-side state, and put it into `params["nonce"]`
yourself. A nonce taken from the client request protects nothing.

#### Signing in with a redirect: `oidc.CodeFlow`

The provider verifies ID tokens. To obtain one in a browser, `CodeFlow` runs
the authorization-code flow with **PKCE (S256), state and nonce**:

```go
flow, err := oidc.NewCodeFlow(g, oidc.CodeFlowConfig{
    RedirectURL:  "https://app.example/auth/google/callback", // registered at Google
    ClientSecret: googleClientSecret,                         // empty for a public client
    Key:          flowKey,                                    // >= 32 bytes, same on every instance
    AuthParams:   map[string]string{"prompt": "select_account"},
})

mux.HandleFunc("GET /auth/google", func(w http.ResponseWriter, r *http.Request) {
    if err := flow.Redirect(w, r, r.URL.Query().Get("next")); err != nil {
        http.Error(w, "bad request", http.StatusBadRequest) // next was not a local path
    }
})
mux.HandleFunc("GET /auth/google/callback", func(w http.ResponseWriter, r *http.Request) {
    cb, err := flow.Callback(w, r)
    if err != nil { /* ErrFlowState: start again; *AuthorizationError: the user canceled */ }
    res, err := svc.Login(r.Context(), iam.AuthRequest{
        Provider: g.Name(), Params: cb.Params, Client: auth.ClientInfo(r),
    })
    if errors.Is(err, iam.ErrUnknownIdentity) { /* offer sign-up: svc.SignUp with the same Params */ }
    auth.StartSession(w, res)
    http.Redirect(w, r, cb.ReturnTo, http.StatusSeeOther)
})
```

- State, nonce and the PKCE verifier live in a short-lived (10 minutes by
  default), **AES-GCM-encrypted** `__Host-` cookie: `HttpOnly`, `Secure`,
  `SameSite=Lax` (the callback is a top-level navigation). No server-side
  store is needed, and any instance with the same `Key` can take the
  callback. Starting another sign-in in the same browser replaces it.
- `Callback` always clears the cookie, compares `state` in constant time,
  checks the `iss` parameter when the provider sends one (RFC 9207), and
  exchanges the code with the verifier. It returns `Params` (`id_token`,
  and the `nonce` from the cookie, never from the request) for
  `Service.Login`, `SignUp` or `LinkIdentity`, so throttling, audit and the
  ID-token checks all apply.
- `ReturnTo` must be a local path (`/settings`); anything that a browser
  could read as another site is rejected by `Start` with
  `ErrInvalidReturnTo`, so the flow cannot be used as an open redirect.
- `RedirectURL` must be `https`, unless `Insecure` is set for local
  development (the cookie then loses `Secure` and the `__Host-` prefix).

## Writing a provider

```go
type magicLink struct{ links LinkStore }

func (magicLink) Name() string { return "magic_link" }

func (m magicLink) Authenticate(ctx context.Context, params map[string]string) (*provider.Identity, error) {
    email, err := m.links.Redeem(ctx, params["token"]) // single-use, expiring
    if err != nil {
        return nil, fmt.Errorf("magic link: %w", provider.ErrInvalidCredentials)
    }
    return &provider.Identity{Provider: "magic_link", ProviderID: email, Email: email, EmailVerified: true}, nil
}
```

Rules:

- Return a **stable** `ProviderID`. Emails can change; prefer an immutable
  ID when the provider has one.
- Wrap credential failures in `provider.ErrInvalidCredentials`, and never
  say which part was wrong.
- Do not return roles. Authorization data belongs to your application.
- Implement `provider.Registrar` (`Register`, `Unregister`) if the provider
  can create credentials during sign-up.

## Linking identities

```go
err := svc.LinkIdentity(ctx, currentSubjectID, iam.AuthRequest{Provider: "google", Params: ...})
```

This authenticates the new identity and links it to an existing subject.
It fails with `iam.ErrIdentityLinked` if the identity belongs to someone
else. IAM never links accounts automatically by email: an unverified email
claim would let anyone take over an account.
