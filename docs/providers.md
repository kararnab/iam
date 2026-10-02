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
  `Service.SignUp` create credentials.

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

The provider verifies ID tokens; it does not run the authorization-code
redirect flow. Use `golang.org/x/oauth2` (or your front end) to obtain the ID
token. Code-flow helpers are planned.

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
