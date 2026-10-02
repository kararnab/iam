# iam

A small, importable authentication and authorization library for Go web
applications and APIs.

`iam` sits between your application and its identity providers. It logs
users in through pluggable providers (passwords, Google, any OpenID Connect
issuer), keeps server-side sessions, issues short-lived access tokens,
evaluates authorization policies and emits audit events. Your application
keeps owning its users and its business logic.

- **Two session modes:** HttpOnly cookie sessions for same-origin web apps
  (the default), or bearer access tokens with rotating refresh tokens for
  APIs and mobile clients. One service can serve both.
- **Secure defaults:** deny-by-default authorization, hashed session secrets
  and refresh tokens, refresh-token reuse detection, argon2id passwords,
  pinned JWT algorithms, CSRF and cross-origin protection, login throttling.
- **Small core:** the core module depends only on the standard library and
  `golang.org/x/crypto`. Integrations are opt-in modules.
- **No HTTP in the core service:** `iam.Service` takes and returns plain data,
  so it can later sit behind gRPC or become a remote service.
  `httpauth` adapts it to `net/http`.

> **Versioning:** the first library release is `v2.0.0`, because this
> repository's earlier tags (`v1.0-nodejs`, `v1.1-golang`) were the demo
> application. Go therefore imports it as `github.com/kararnab/iam/v2`. It
> follows semantic versioning: no breaking changes within v2. See the
> [changelog](CHANGELOG.md).

## Modules

| Module | Adds | Dependencies |
|---|---|---|
| `github.com/kararnab/iam/v2` | service, sessions, JWT, passwords, policy, invites, rate limiting, `httpauth`, in-memory stores | stdlib, `golang.org/x/crypto` |
| `github.com/kararnab/iam/oidc/v2` | Google and OpenID Connect sign-in | `coreos/go-oidc` |
| `github.com/kararnab/iam/paseto/v2` | PASETO v4 access tokens | `aidanwoods.dev/go-paseto` |
| `github.com/kararnab/iam/pgstore/v2` | PostgreSQL stores and migrations | `jackc/pgx/v5` |
| `github.com/kararnab/iam/redisstore/v2` | Redis session store and shared rate limiter | `redis/go-redis/v9` |
| `github.com/kararnab/iam/prometheus/v2` | Prometheus metrics | `prometheus/client_golang` |

```sh
go get github.com/kararnab/iam/v2
go get github.com/kararnab/iam/pgstore/v2   # only what you use
```

Requires Go 1.26 or later.

## Five-minute guide: a net/http app with cookie sessions and invites

The complete program is [`examples/quickstart`](examples/quickstart/main.go).

**1. Users and passwords.** Users belong to your application. `memstore`
keeps them in memory; use [`pgstore`](docs/stores.md) or implement
`iam.UserStore` over your own tables.

```go
users := memstore.NewUsers()
hasher, _ := password.NewArgon2id(password.DefaultParams, 0)
passwords, _ := password.NewProvider(users, hasher, password.DefaultPolicy)
```

**2. A policy.** Roles grant actions on resource types. Anything not granted
is denied.

```go
rbac, _ := policy.NewRBAC(map[string][]policy.Permission{
    "admin":  {policy.P(policy.Wildcard, policy.Wildcard)},
    "member": {policy.P("read", "note")},
})
```

**3. The service.** Cookie sessions are the default mode, and sign-up is
invite-only once an invite store is configured.

```go
svc, err := iam.New(iam.Config{
    Providers: []provider.AuthProvider{passwords},
    Users:     users,
    Sessions:  memstore.NewSessions(),
    Policy:    rbac,
    Signup:    iam.SignupConfig{Invites: memstore.NewInvites()},
})
```

**4. HTTP.** `httpauth` sets the session cookie (HttpOnly, SameSite=Lax,
`__Host-` prefix, Secure), checks CSRF tokens and authorizes requests.

```go
auth, _ := httpauth.New(httpauth.Config{
    Service: svc,
    Cookie:  httpauth.CookieConfig{Insecure: true}, // plain-HTTP localhost only!
})

mux := http.NewServeMux()
mux.HandleFunc("POST /signup", func(w http.ResponseWriter, r *http.Request) {
    // ...decode username, password and invite...
    res, err := svc.SignUp(r.Context(), iam.SignUpRequest{
        InviteToken: c.Invite,
        Provider:    password.ProviderName,
        Params:      map[string]string{"username": c.Username, "password": c.Password},
        Client:      auth.ClientInfo(r),
    })
    if err != nil { /* 403 */ }
    csrf := auth.StartSession(w, res) // sets the cookie
    // ...send csrf to the page; it must accompany POST/PUT/DELETE...
})
// POST /login is the same with svc.Login; POST /logout calls auth.EndSession.

mux.Handle("GET /notes", auth.RequirePermission("read", "note", nil)(notesHandler))

inv, _ := svc.CreateInvite(ctx, iam.InviteRequest{Roles: []string{"member"}})
log.Printf("invite token: %s", inv.Token)

http.ListenAndServe("localhost:8080", auth.Protect(mux))
```

**5. Try it.**

```sh
go run ./examples/quickstart     # prints an invite token
INVITE=...                       # paste it

curl -c jar localhost:8080/signup \
  -d "{\"username\":\"ana@example.com\",\"password\":\"correct horse battery staple\",\"invite\":\"$INVITE\"}"
# {"csrf_token":"…","subject":{"id":"J7NS…","roles":["member"]}}

curl -b jar localhost:8080/notes                            # {"hello":"J7NS…"}
curl -b jar -X POST localhost:8080/logout                    # 403: CSRF token required
curl -b jar -c jar -X POST -H "X-CSRF-Token: …" localhost:8080/logout   # 200
curl -b jar localhost:8080/notes                            # 401
```

Set `ADDR` if port 8080 is taken. To allow anyone to register, use
`Signup: iam.SignupConfig{Policy: invite.Open, DefaultRoles: []string{"member"}}`.

### Adding bearer tokens for API clients

Allow the mode, add a token issuer and verifier, and accept bearer
credentials in `httpauth`:

```go
kp := keys.NewMemoryProvider(keys.Key{ID: "k1", Alg: keys.HS256, Secret: secret32bytes})
jc := jwt.Config{Issuer: "my-app", Audience: "my-api"}
issuer, _ := jwt.NewIssuer(kp, jc)
verifier, _ := jwt.NewVerifier(kp, jc)

svc, _ := iam.New(iam.Config{
    // ...as above...
    AllowedModes:  []session.Mode{session.ModeCookie, session.ModeBearer},
    TokenIssuer:   issuer,
    TokenVerifier: verifier,
})
auth, _ := httpauth.New(httpauth.Config{Service: svc, Modes: []session.Mode{session.ModeCookie, session.ModeBearer}})
```

`svc.Login(ctx, iam.AuthRequest{..., Mode: session.ModeBearer})` then returns an
access token (10 minutes by default) and a refresh token. Every
`svc.Refresh` rotates the refresh token. Presenting an old refresh token
again revokes the whole session.

## Concepts

- **Subject:** the canonical user. `Subject.ID` is your application's ID,
  never a provider's. One subject can sign in through several providers
  (`IdentityStore`, `Service.LinkIdentity`). Roles always come from your store.
- **Session:** server-side, in both modes. Clients only ever hold a random
  256-bit secret; stores keep its SHA-256 hash. Sessions have idle and
  absolute timeouts, can be listed, and can be revoked one by one or all at
  once ("log out everywhere").
- **Policy:** an `Engine` decides; `RBAC` covers roles. `policy.AnyOf` and
  `policy.AllOf` combine it with your own rules, for example resource
  ownership. Every denial is audited.
- **Audit and metrics:** security events (logins, refreshes, reuse
  detection, lockouts, denials, sign-ups) go to an `audit.Logger`, and
  counters go to a `metrics.Recorder`.

## Extension points

Each one is an interface with an in-memory or standard-library reference
implementation:

- [Identity providers](docs/providers.md): password, OIDC/Google, your own
- [Stores](docs/stores.md): users and identities, sessions, invites (memory, PostgreSQL, Redis, your own)
- [Policy](docs/policy.md): RBAC, composition, custom engines
- [Audit](docs/audit.md): event types and sinks
- [Metrics](docs/metrics.md): counters and Prometheus
- [Access tokens](docs/tokens.md): JWT, PASETO, key rotation

Also: [architecture](docs/architecture.md) and [security model](SECURITY.md).

## The demo app

[`examples/demo`](examples/demo) is a books API that uses the library the way
any consumer would: cookie and bearer endpoints, invite-only sign-up, RBAC,
session management, throttling, Prometheus, and optional PostgreSQL. See
its [README](examples/demo/README.md).

## Development

```sh
./scripts/each-module.sh go test -race ./...     # every module

# Integration tests for pgstore, redisstore and the demo on PostgreSQL:
export IAM_TEST_POSTGRES_DSN='postgres://postgres:pw@localhost:5432/iamtest?sslmode=disable'
export IAM_TEST_REDIS_ADDR='localhost:6379'

go test ./token/jwt -run '^$' -fuzz FuzzVerify    # fuzzing (see .github/workflows/fuzz.yml)
```

CI runs `go vet`, `gofmt`, `staticcheck`, `govulncheck` and `go test -race`
on every module with Go 1.26 and 1.27.

## License

[MIT](LICENSE)
