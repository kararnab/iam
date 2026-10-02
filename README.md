# iam: authentication and authorization for Go web apps

[![Go Reference](https://pkg.go.dev/badge/github.com/kararnab/iam/v2.svg)](https://pkg.go.dev/github.com/kararnab/iam/v2)
[![CI](https://github.com/kararnab/iam/actions/workflows/ci.yml/badge.svg)](https://github.com/kararnab/iam/actions/workflows/ci.yml)
[![Go version](https://img.shields.io/github/go-mod/go-version/kararnab/iam)](go.mod)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Logins, sessions, JWT, RBAC and invites for Go web apps and APIs, with
secure defaults. It is one library to import, not another server to run.**

`iam` gives your Go application password and Google/OIDC sign-in,
server-side sessions (HttpOnly cookies for browsers, rotating refresh tokens
for APIs and mobile), deny-by-default role-based access control,
invite-only sign-up, login throttling and audit logs. It works with
`net/http`, keeps your users in your own database, and depends only on the
standard library and `golang.org/x/crypto`.

```go
svc, _ := iam.New(iam.Config{
    Providers: []provider.AuthProvider{passwords},   // + oidc.NewGoogle(...)
    Users:     users,                                // your user table, or pgstore
    Sessions:  memstore.NewSessions(),               // or pgstore / redisstore
    Policy:    rbac,                                 // nothing is allowed until you grant it
})
auth, _ := httpauth.New(httpauth.Config{Service: svc})

mux.Handle("GET /notes", auth.RequirePermission("read", "note", nil)(notes))
http.ListenAndServe(":8080", auth.Protect(mux))      // sessions, CSRF, cross-origin checks
```

Try it in ten seconds, with no clone needed:

```sh
go run github.com/kararnab/iam/v2/examples/quickstart@latest
```

## Why iam?

You could combine a JWT library, a session manager, an OAuth helper and a
policy engine, and then write the glue that gets security wrong:
refresh-token reuse, CSRF on cookie sessions, user enumeration, roles that
go stale after a refresh. `iam` is that glue, designed together and tested
together.

| | Login providers | Sessions | Access tokens | Authorization | Runs as |
|---|:-:|:-:|:-:|:-:|---|
| **iam** | password, Google, OIDC | ✅ cookie + bearer, rotation | ✅ JWT, PASETO | ✅ RBAC + your rules | a library |
| golang-jwt/jwt | – | – | ✅ JWT | – | a library |
| alexedwards/scs | – | ✅ cookie | – | – | a library |
| markbates/goth | ✅ many OAuth | – | – | – | a library |
| casbin | – | – | – | ✅ many models | a library |
| Ory Kratos, Keycloak, Zitadel | ✅ | ✅ | ✅ | partly | a separate server |

Those are excellent tools; choose them when you need only their part, or
when you want a separate identity server. `iam` doesn't do everything yet.
If you need password reset, MFA or passkeys today, see the
[roadmap](#roadmap).

## Features

- 🍪 **Two session modes:** HttpOnly, `__Host-` cookie sessions for browsers
  (the default), and short-lived access tokens with **rotating refresh
  tokens** for APIs and mobile apps. One service can serve both.
- 🔁 **Refresh-token reuse detection:** replaying an old refresh token
  revokes the whole session.
- 🔑 **Sign-in:** argon2id passwords (bcrypt hashes are upgraded
  automatically), Google and any OpenID Connect issuer, plus **identity
  linking**: one user, many ways to sign in.
- 🛡️ **Deny-by-default RBAC**, composable with your own rules (for example
  "owners can edit").
- ✉️ **Invite-only sign-up** with single-use, expiring invites, switchable to
  open or closed.
- 🚦 **Login throttling** per account and per IP, on by default.
- 🧾 **Audit events** (logins, reuse detection, lockouts, denials) through
  `log/slog`, and **Prometheus** metrics.
- 👀 **Session management:** list devices, revoke one, "log out everywhere
  else".
- 🧩 **Pluggable everything:** providers, stores (memory, PostgreSQL, Redis,
  yours), policy engines, token formats (JWT, PASETO), audit sinks.
- 🪶 **Small core:** standard library and `golang.org/x/crypto` only.
  Integrations are opt-in modules.

### Built to be trusted

- A [threat model](SECURITY.md) with documented defaults, and a list of
  what the library deliberately does not do.
- Fuzz tests for every parser this library implements for untrusted input:
  JWT, PASETO, session cookies, password hashes. They run weekly in CI.
- A [store conformance suite](storetest) that the memory, PostgreSQL and
  Redis stores all pass, including concurrent-rotation races.
- `go test -race`, `staticcheck` and `govulncheck` on every module, with
  Go 1.26 and 1.27.
- End-to-end tests of every flow in the [demo app](examples/demo), on
  PostgreSQL.

## Install

```sh
go get github.com/kararnab/iam/v2
```

Add only the integrations you use:

| Module | Adds | Dependencies |
|---|---|---|
| `github.com/kararnab/iam/v2` | service, sessions, JWT, passwords, policy, invites, rate limiting, `httpauth`, in-memory stores | stdlib, `golang.org/x/crypto` |
| `github.com/kararnab/iam/oidc/v2` | Google and OpenID Connect sign-in | `coreos/go-oidc` |
| `github.com/kararnab/iam/paseto/v2` | PASETO v4 access tokens | `aidanwoods.dev/go-paseto` |
| `github.com/kararnab/iam/pgstore/v2` | PostgreSQL stores and migrations | `jackc/pgx/v5` |
| `github.com/kararnab/iam/redisstore/v2` | Redis session store and shared rate limiter | `redis/go-redis/v9` |
| `github.com/kararnab/iam/prometheus/v2` | Prometheus metrics | `prometheus/client_golang` |

Requires Go 1.26 or later. Versions follow semantic versioning. The first
release is v2.0.0 because this repository's earlier tags belonged to the
demo application. See the [changelog](CHANGELOG.md).

## Five-minute guide: a net/http app with cookie sessions and invites

The complete program is [`examples/quickstart`](examples/quickstart/main.go).

```go
import (
    "github.com/kararnab/iam/v2"
    "github.com/kararnab/iam/v2/httpauth"
    "github.com/kararnab/iam/v2/memstore"
    "github.com/kararnab/iam/v2/password"
    "github.com/kararnab/iam/v2/policy"
    "github.com/kararnab/iam/v2/provider"
)
```

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
go run github.com/kararnab/iam/v2/examples/quickstart@latest   # prints an invite token
INVITE=...                                                      # paste it

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
- **No HTTP in the core service:** `iam.Service` takes and returns plain
  data, so it can later sit behind gRPC or become a remote service.
  `httpauth` adapts it to `net/http`.

## Documentation

- [API reference on pkg.go.dev](https://pkg.go.dev/github.com/kararnab/iam/v2)
- Extension points, each an interface with a reference implementation:
  - [Identity providers](docs/providers.md): password, OIDC/Google, your own
  - [Stores](docs/stores.md): users and identities, sessions, invites (memory, PostgreSQL, Redis, your own)
  - [Policy](docs/policy.md): RBAC, composition, custom engines
  - [Audit](docs/audit.md): event types and sinks
  - [Metrics](docs/metrics.md): counters and Prometheus
  - [Access tokens](docs/tokens.md): JWT, PASETO, key rotation
- [Architecture](docs/architecture.md) and the [security model](SECURITY.md)

## The demo app

[`examples/demo`](examples/demo) is a books API that uses the library the way
any consumer would: cookie and bearer endpoints, invite-only sign-up, RBAC,
session management, throttling, Prometheus, and optional PostgreSQL. See
its [README](examples/demo/README.md) and [OpenAPI spec](examples/demo/openapi.yaml).

## Roadmap

Planned, roughly in this order. Upvotes and comments on issues help decide.

- OIDC authorization-code flow helpers (redirect, PKCE, state)
- Password reset and email verification, reusing the invite-token machinery
- TOTP multi-factor authentication
- WebAuthn and passkeys
- Publishing JWKS for EdDSA access tokens

`iam` will not become an OAuth 2.0 authorization server; see
[SECURITY.md](SECURITY.md#what-the-library-deliberately-does-not-do).

## Contributing

Issues and pull requests are welcome, especially new stores, providers,
and examples for other routers (chi, echo, gin). Please open an issue
before large changes. Report security problems privately as described in
[SECURITY.md](SECURITY.md).

```sh
./scripts/each-module.sh go test -race ./...     # every module

# Integration tests for pgstore, redisstore and the demo on PostgreSQL:
export IAM_TEST_POSTGRES_DSN='postgres://postgres:pw@localhost:5432/iamtest?sslmode=disable'
export IAM_TEST_REDIS_ADDR='localhost:6379'

go test ./token/jwt -run '^$' -fuzz FuzzVerify    # fuzzing (see .github/workflows/fuzz.yml)
```

If `iam` saves you time, a ⭐ helps other Go developers find it.

## License

[MIT](LICENSE)
