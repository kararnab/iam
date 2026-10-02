# Plan: turn `pkg/iam` into a reusable Go authentication library

Status: **approved 2026-10-02** (all recommendations D1–D19 accepted).
Branch: `feature/reusable-iam`.
Date: 2026-10-02.

This plan covers four things: the decisions that need your sign-off (each with a recommendation), the
problems found while reading the repository, the target layout and APIs, every breaking change, and
the phases of work.

---

## 0. What I found while reading the repository

Some of these you already listed. The others are new and are marked **(new)**.

| # | Where | Problem | Severity |
|---|-------|---------|----------|
| F1 | `go.mod` | **(new)** The module path is `github.com/kararnab/authdemo`, but the repository is `github.com/kararnab/AuthSystemDemo`. Today nobody can `go get` it. | blocker |
| F2 | `cmd/server/main.go`, `pkg/secret_store/store.go` | **(new)** `BuildSecretStore` only uses `DummyStore`, because `NewEnvStore()` is commented out. The running server therefore signs JWTs with the hard-coded key `dev-secret` and seeds an admin `admin@gmail.com` / `p@$$w0rd1`. Anyone who reads the repository can forge admin tokens for any deployment of it. The committed `.env` uses a different variable name (`JWT_SECRET_KEY`) that the code never reads, but it still has to be rotated. | critical |
| F3 | `.env` | Committed since `f05c132` (the initial commit). Deleting it now does not remove it from git history. | high |
| F4 | `service.Refresh` | The new access token contains only `SubjectID`, so roles and attributes are lost. (known) | high |
| F5 | `service.Authenticate` | `Subject.ID` is set to the provider's ID, and roles come from the provider, so a Google user and a password user can never be the same person. (known) | high |
| F6 | `session/*` | Session IDs and refresh tokens are stored in plain text. There is no rotation and no reuse detection. (known) | high |
| F7 | `policy/default.go` | Everything is allowed unless the resource type is `admin`. (known) | high |
| F8 | `token/jwt/verifier.go` | It accepts any HMAC algorithm (HS256, HS384 or HS512), does not check the audience, applies no leeway, and accepts an empty `sub`. `kid` is ignored, and `MultiVerifier` tries every key in turn. (known, plus details) | high |
| F9 | `provider/oidc/providerImpl.go` | **(new)** `SkipIssuerCheck: true`. A validly signed ID token from a *different* issuer that uses the same discovery keys would be accepted. | high |
| F10 | `session/memory_store.go` `Get` | **(new)** It calls `delete()` on the map while holding only `RLock`. This is a data race that can crash the process with `concurrent map writes` under load. | high |
| F11 | `cmd/server` + `internal/api/key_rotation.go` | **(new)** The JWT issuer copies `ActiveKey()` once when the server starts, so after `/admin/keys/rotate` it **keeps signing with the old key**. Rotation does nothing for issuing, and the endpoint returns the new key in the HTTP response. | high |
| F12 | `provider/inhouse` | **(new)** When the username is unknown, bcrypt is skipped, so response timing reveals which usernames exist. | medium |
| F13 | `internal/api/auth_handlers.go` `Register` | **(new)** Anyone can register (this ties in with the invite-only goal). No password length rules, and no limit on request body size. | medium |
| F14 | `service.New` | **(new)** `Metrics` is not checked for nil, so a nil `Metrics` panics on the first call. `Options.SessionStore` is required but never used. | medium |
| F15 | `token/jwt` | **(new)** HMAC keys have no minimum length (`dev-secret` is 10 bytes). | medium |
| F16 | `token/paseto` | **(new)** `github.com/o1egl/paseto` is unmaintained and only supports v2. The `kid` sits inside the encrypted payload, so it cannot be used to pick a key. | medium |
| F17 | `cmd/server` | **(new)** `http.ListenAndServe` runs with no timeouts (slowloris), and `/metrics` is public. | low (demo) |
| F18 | `iam.AuthResult` | **(new)** The struct has no JSON tags, so the API returns `AccessToken` while the OpenAPI spec implies snake_case. The OpenAPI spec also says book IDs are integers, but they are strings. | low |
| F19 | everything | No tests at all. `go vet` is clean. | — |

Randomness check: session IDs come from 32 bytes of `crypto/rand`, which is fine. The new design keeps
this and adds hashing.

---

## 1. Decisions (please approve or change each)

### D1. Module path and repository
- **Recommendation:** rename the GitHub repository `kararnab/AuthSystemDemo` to `kararnab/iam`. GitHub
  redirects the old URL. The root module becomes **`github.com/kararnab/iam`**. That gives short imports
  (`iam`, `iam/session`, `iam/httpauth`) and clean tags (`v0.1.0`, `oidc/v0.1.0`).
- Alternative A: keep the repository name. The module path is then `github.com/kararnab/AuthSystemDemo`
  with mixed case, which works but reads badly in imports.
- Alternative B: put the library in a nested `iam/` module of this repository
  (`github.com/kararnab/AuthSystemDemo/iam`). Tags would have to be `iam/v0.1.0`, `iam/oidc/v0.1.0`.
- You have to do the rename on GitHub yourself. I won't push anything.
- **Timing (agreed):** the rename happens **last**, after P9. Until then the code already uses
  `github.com/kararnab/iam`. This works locally and in CI because the modules point at each other
  through `replace` directives. Only external `go get` and tags depend on the rename. Final order:
  rename the repository, `git remote set-url origin git@github.com:kararnab/iam.git`, push, then tag.

### D2. Packages in the core module
- **Recommendation:** the default service implementation moves into the root package as
  `iam.New(iam.Config)`. The `service` sub-package goes away. The `iam.Service` interface stays, so the
  core can still be swapped for a remote client.
- Every package that defines a store interface also ships its in-memory implementation in a single
  `memstore` package, so tests and the demo wire one object.

### D3. JWT implementation: the core may only use the standard library and x/crypto
`golang-jwt/jwt` can't stay in core.
- **Recommendation:** write a small JWS compact implementation in `token/jwt` using only the standard
  library (about 250 lines). It allows only **HS256** (minimum 32-byte key) and **EdDSA/Ed25519**. Each
  key is fixed to one algorithm, so algorithm confusion and `alg: none` can't happen by construction. It
  will be tested against the RFC 7515 and RFC 8037 vectors and fuzzed.
- Alternative: move the `golang-jwt/jwt/v5` version into a `jwt` sub-module. Bearer mode would then need
  a sub-module, and core would ship no access-token format of its own.

### D4. Session modes
- **Recommendation:** use one `Session` record for both modes. Each `Login` call asks for a mode
  (`AuthRequest.Mode`), which must be one of `Config.AllowedModes`. The default is `[Cookie]`. A single
  service can then serve the web app (cookie) and a mobile app (bearer) at the same time.
- **Cookie mode:** the cookie holds 32 random bytes in base64url. The cookie is not signed, because a
  signature adds nothing to an unguessable opaque value. The cookie is named `__Host-session` when
  `Secure` is set, and `session` in development when `Secure=false`. It is `HttpOnly`,
  `SameSite=Lax` (configurable to `Strict`) and `Path=/`, with no `Domain`. Sessions have an idle timeout
  (default 30 minutes) and an absolute timeout (default 7 days). A new ID is issued on every login and
  when `Service.RotateSession` is called, to prevent session fixation.
- **Bearer mode:** access tokens have a 10-minute TTL by default. Refresh tokens are opaque and rotated
  on every use. The session's public ID is the token family.
- **Per-request subject in cookie mode:** load the subject from the consumer's `SubjectLoader` on every
  request, so role changes take effect immediately. Caching is left to the consumer, who can wrap the
  loader.

### D5. Stored secrets: hashing and rotation
- Session secrets, refresh tokens and invite tokens are 256-bit random values. Only their **SHA-256**
  is stored, and lookups go **by hash**. A slow hash or a pepper is unnecessary for 256-bit random
  inputs. Lookup by hash also means an attacker can't use database or map timing to learn anything
  about a token they don't already hold.
- Each session keeps a `current_token_hash`. On refresh, the store does an atomic compare-and-swap from
  the old hash to the new one, and the old hash goes into a `rotated` set. Presenting a rotated hash
  revokes the **whole session (family)** and emits `refresh_reuse_detected`.
- **Recommendation:** add `ReuseGrace` (default `0`). Inside the grace window, a reuse of the
  *immediately previous* token fails with `ErrRefreshRaced` but does not revoke anything. This covers
  clients that send two refreshes in parallel.

### D6. Canonical subject and identity linking
The consumer implements these small interfaces:
```go
type SubjectLoader   interface { LoadSubject(ctx, subjectID string) (*Subject, error) }            // roles, attrs, Disabled
type IdentityStore   interface {
    ResolveIdentity(ctx, provider, providerID string) (subjectID string, err error)                // ErrNotFound
    LinkIdentity(ctx, subjectID string, id provider.Identity) error
    UnlinkIdentity(ctx, subjectID, provider, providerID string) error
    CreateSubject(ctx, id provider.Identity, grant SignupGrant) (subjectID string, err error)       // only called when sign-up is allowed
}
```
- `Subject.ID` always holds the canonical internal ID. Roles come **only** from the application's store,
  never from the provider. `provider.Identity.Roles` is removed.
- **Recommendation:** identities are **never** linked automatically by email, because an unverified
  email claim would allow account takeover. Linking happens only through
  `Service.LinkIdentity(ctx, subjectID, AuthRequest)` by an already authenticated subject. An unknown
  identity at login is rejected, unless the sign-up policy allows creating a new subject.

### D7. Refresh reloads the subject
`Refresh` loads the subject through `SubjectLoader`. If the subject is missing or `Disabled`, the
session is revoked and `ErrSubjectDisabled` is returned. `Refresh` now returns a `*TokenPair` with a
new access token and a new refresh token.

### D8. Access-token claims
The claims are `iss`, `aud` (required), `sub` (canonical ID), `iat`, `nbf`, `exp`, `jti`, `sid` (the
session's public ID), `roles` and `attrs`. The header carries `typ: at+jwt` (RFC 9068), so an ID token
can't be passed off as an access token.

The verifier checks the configured algorithm, the `kid` (looked up directly, not by trying every key),
`iss`, `aud` and `exp`/`nbf`, with leeway defaulting to 30 seconds and capped at 2 minutes. It requires
a non-empty `sub` and rejects input longer than 8 KiB.

- **Recommendation:** `Config.VerifySessionOnAccess` defaults to `false`. Verification stays stateless,
  so a revocation takes effect for bearer access tokens within their 10-minute TTL. Setting it to `true`
  adds a session lookup by `sid`, which makes revocation immediate.

### D9. Policy
- `iam.New` returns an error when no engine is configured. `policy.DenyAll` exists, and `DefaultPolicy`
  is removed.
- `policy.RBAC` is configured as `map[Role][]Permission{ {Action, ResourceType} }`. A `*` wildcard is
  allowed for action and for resource type. Explicit deny rules are not included in v0.1.
- `policy.Chain(engines...)` returns the first decision that is not "no opinion". `policy.Func` adapts a
  plain function, which is how a consumer adds ownership or ABAC checks.
- If the engine returns an error, the result is **deny**, and the denial is audited.

### D10. Password hashing
- The `password.Hasher` interface has `Hash`, `Verify` and `NeedsRehash`. Argon2id hashes use the PHC
  string format `$argon2id$v=19$m=…,t=…,p=…$salt$hash`.
- **Recommended default parameters:** the OWASP baseline `m=19 MiB, t=2, p=1`, all configurable. A
  semaphore (default `GOMAXPROCS`) limits how many hashes run at once, so a burst of logins can't exhaust
  memory.
- `bcrypt` is supported for verification only. After a successful login, `NeedsRehash` reports true and
  the password provider re-hashes with argon2id through `CredentialStore.SetPasswordHash`.
- When the username is unknown, the provider still verifies against a fixed dummy hash, so timing does
  not reveal whether a user exists (fixes F12).
- Passwords must be at least **12** and at most **1024** bytes by default, both configurable.

### D11. Sign-up and invites
- `Config.Signup` is `Closed`, `InviteOnly` (the default) or `Open`.
- Invites are single-use and expire (default 7 days). An invite can optionally be bound to an email
  address, and it can carry roles, which are handed to `IdentityStore.CreateSubject` as a `SignupGrant`.
  `invite.Store.Consume(hash)` is atomic.
- `Service.CreateInvite` returns the token **once**. Delivering it is the consumer's job, because the
  library sends no email.

### D12. Rate limiting and lockout
- `ratelimit.Limiter` has `Allow(ctx, key) (Result, error)` and `Reset(ctx, key)`. The in-memory
  implementation uses fixed windows and the standard library only (no `x/time/rate`, because of the
  dependency rule).
- The service checks two keys: `login:<normalized identifier>` and `ip:<client ip>`.
- **Recommendation:** throttle by default with a growing back-off rather than locking accounts hard,
  because a hard lockout lets anyone lock any user out. The `LockoutHooks` interface
  (`OnFailure(ctx, key, n)` and `OnLocked`) lets a consumer add a hard lockout or notifications.
- The client IP reaches the service as plain data in `AuthRequest.Client{IP, UserAgent}`.
  `httpauth` fills it in from `RemoteAddr`. `X-Forwarded-For` is trusted **only** for proxies listed in
  `TrustedProxies`, which is empty by default.

### D13. HTTP layer (`httpauth`, standard library only)
- The package depends only on the `iam.Service` interface, so it also works against a remote service.
  The core service still contains no HTTP code.
- It provides `Authenticate` (an anonymous request is allowed through), `RequireAuth`,
  `RequireRole(role)`, `RequirePermission(action, resourceType, idFn)`, `SubjectFrom(ctx)`,
  `SessionFrom(ctx)` and `WithSubject` (for tests). `StartSession` and `EndSession` set and clear the
  cookie. `ErrorHandler` is configurable, with JSON as the default.
- **CSRF (cookie mode), recommendation:** layer the standard library's
  `http.CrossOriginProtection` (Go 1.25+, based on Fetch Metadata and `Origin`) with a per-session
  **synchronizer token**: `HMAC(session-csrf-key, session public ID)`. It is sent in the
  `X-CSRF-Token` header or a form field and compared with `subtle.ConstantTimeCompare`. Both are on by
  default for unsafe methods.

### D14. Audit and metrics
- New audit events: `login_success`, `login_failure`, `logout`, `session_created`, `refresh_success`,
  `refresh_failure`, `refresh_reuse_detected`, `session_revoked`, `sessions_revoked_all`,
  `policy_denied`, `signup`, `invite_created`, `invite_consumed`, `rate_limited`, `lockout` and
  `identity_linked`.
- `audit.Event` gains `Time`, `SessionID` (the public ID, never the secret), `ClientIP` and `Outcome`.
  The default `audit.SlogLogger` uses `log/slog`.
- **Recommendation:** replace `metrics.IAMMetrics` with `metrics.Recorder{ Inc(Event) }`, where `Event` is
  an enum with low-cardinality values. Adding an event later then doesn't break the interface.
  `metrics.Noop` is used when nothing is configured (fixes F14).

### D15. Supported Go versions
- **Recommendation:** set the `go` directive to `1.26` and run CI on **1.26.x and 1.27.x**, the two
  releases Go currently supports. The local toolchain is 1.27.1. This raises the minimum from today's
  `1.25.4`.

### D16. OIDC scope
- **Recommendation:** for v0.1, the `oidc` sub-module verifies ID tokens only, as it does today. It
  checks the issuer (no `SkipIssuerCheck`), checks `nonce` when one is supplied, and exposes
  `email_verified`. `oidc.NewGoogle(clientID)` accepts both of Google's issuer spellings explicitly.
- Helpers for the authorization-code flow with PKCE (redirect, state, callback) are left for v0.2,
  following the "IAM does not implement OAuth flows" principle.

### D17. Postgres migrations and tests
- **Recommendation:** ship the SQL files with `embed` and add a small `pgstore.Migrate(ctx, pool)` that
  records applied versions in an `iam_schema_migrations` table. There is no migration library
  dependency, and consumers who prefer their own tool can copy the `.sql` files.
- Postgres and Redis integration tests run against CI service containers. They are skipped when
  `IAM_TEST_POSTGRES_DSN` or `IAM_TEST_REDIS_ADDR` is not set, so the project doesn't need
  testcontainers.

### D18. What happens to `pkg/log`, `pkg/secret_store`, `pkg/metrics`
- The library logs through `log/slog`. `pkg/log` with its zerolog adapter and `pkg/secret_store` move
  into the demo as `examples/demo/internal/...`, or are deleted where `slog` and environment variables
  are enough. **Recommendation:** delete `pkg/log` and use `slog` in the demo. Move `secret_store` to the
  demo and enable the env store with fail-closed behaviour: the demo refuses to start without
  `IAM_SIGNING_KEY`, except in an explicit `-dev` mode that generates a random key on each run (fixes
  F2).

### D19. `.env` and git history
- Remove `.env`, add `.env.example`, and add `.env` to `.gitignore`.
- **You need to rotate** whatever `JWT_SECRET_KEY` held. Also treat `dev-secret` and the demo admin
  password as public.
- Rewriting history (`git filter-repo`) would need a force-push. **Recommendation:** don't rewrite. Rotate
  the secret instead, because the value has been public since the first commit.

---

## 2. Target layout

```
/                                   module github.com/kararnab/iam            (stdlib + x/crypto)
├── iam.go  config.go  service.go   Service interface, Subject, AuthRequest, Config, New, errors
├── provider/                       AuthProvider, Identity, optional Registrar interface
│   └── password/                   username/password provider (replaces inhouse)
├── password/                       Hasher, argon2id, bcrypt-verify, PHC encoding
├── session/                        Session, Store, rotation and reuse logic, token generation and hashing
├── token/                          Issuer, Verifier, Claims
│   ├── jwt/                        stdlib JWS (HS256, EdDSA), pinned alg/iss/aud/leeway
│   └── keys/                       Key{ID, Alg, Material}, Provider, MemoryProvider (rotation-safe)
├── policy/                         Engine, Decision, DenyAll, RBAC, Chain, Func
├── invite/                         Invite, Store, SignupPolicy
├── ratelimit/                      Limiter, LockoutHooks, memory limiter
├── audit/                          Logger, Event, SlogLogger, Multi
├── metrics/                        Recorder, Noop
├── memstore/                       in-memory Users/Identities/Credentials, Sessions, Invites (reference impls)
├── httpauth/                       net/http middleware, cookies, CSRF, context helpers
├── internal/randutil/              crypto/rand token generation, SHA-256 helpers
│
├── oidc/          go.mod           module github.com/kararnab/iam/oidc        (go-oidc)
├── prometheus/    go.mod           module github.com/kararnab/iam/prometheus  (client_golang)
├── paseto/        go.mod           module github.com/kararnab/iam/paseto      (go-paseto v4)
├── pgstore/       go.mod           module github.com/kararnab/iam/pgstore     (pgx/v5) + migrations/*.sql
├── redisstore/    go.mod           module github.com/kararnab/iam/redisstore  (go-redis/v9)  sessions + limiter
│
├── examples/demo/ go.mod           module github.com/kararnab/iam/examples/demo
│   ├── main.go                     stdlib ServeMux, slog, cookie + bearer, invites, books RBAC
│   ├── internal/{books,users,config,secrets}
│   ├── e2e_test.go                 httptest end-to-end flows
│   ├── openapi.yaml  Dockerfile
│
├── docs/  (README per extension point, plan)   SECURITY.md   CHANGELOG.md   .env.example
└── .github/workflows/ci.yml
```

Sub-modules and the demo use `replace ../` directives while developing. Before a release tag, the
`replace` lines in sub-modules are dropped in favour of the tagged core version. The demo keeps its
`replace`, since it is never imported. `go.work` stays gitignored.

### `iam.Service` (sketch; every argument and result is plain data, so it can be exposed remotely)
```go
type Service interface {
    Login(ctx, AuthRequest) (*LoginResult, error)                 // was Authenticate
    SignUp(ctx, SignUpRequest) (*LoginResult, error)
    Refresh(ctx, refreshToken string, c ClientInfo) (*TokenPair, error)
    ValidateSession(ctx, sessionToken string) (*Subject, *SessionInfo, error)   // cookie mode
    VerifyAccessToken(ctx, accessToken string) (*Subject, error)               // bearer mode
    Authorize(ctx, *Subject, policy.Action, policy.Resource) (*policy.Decision, error)
    Logout(ctx, sessionOrRefreshToken string) error               // was Revoke
    RotateSession(ctx, sessionToken string) (*LoginResult, error)
    ListSessions(ctx, subjectID string) ([]SessionInfo, error)
    RevokeSession(ctx, subjectID, sessionID string) error
    RevokeAllSessions(ctx, subjectID string, exceptSessionID string) error     // "log out everywhere"
    CreateInvite(ctx, InviteRequest) (*IssuedInvite, error)
    LinkIdentity(ctx, subjectID string, req AuthRequest) error
}
```

---

## 3. Dependencies (one line each)

| Module | Dependency | Why |
|---|---|---|
| core | `golang.org/x/crypto` | argon2id and bcrypt are not in the standard library. |
| oidc | `github.com/coreos/go-oidc/v3` | OIDC discovery, JWKS caching and ID-token verification. Writing these ourselves would be risky. It also **removes** `google.golang.org/api` (and with it gRPC and OpenTelemetry). |
| prometheus | `github.com/prometheus/client_golang` | The standard way to expose Prometheus metrics. |
| paseto | `aidanwoods.dev/go-paseto` | A maintained library for PASETO v4. It replaces the unmaintained, v2-only `o1egl/paseto`. |
| pgstore | `github.com/jackc/pgx/v5` | The de facto Postgres driver, with native types and pooling. |
| redisstore | `github.com/redis/go-redis/v9` | The official Redis client. Lua scripts give atomic rotation and atomic counters. |
| demo | none beyond the above | `go-chi/chi`, `google/uuid` and `rs/zerolog` are **dropped** in favour of the 1.22+ `ServeMux` patterns, `crypto/rand` and `log/slog`. |
| CI only | `staticcheck`, `govulncheck` | Run with `go run …@version` in CI. They are not module dependencies. |

---

## 4. Breaking changes (relative to `github.com/kararnab/authdemo/pkg/iam` at `71ab8e2`)

1. **Module path:** `github.com/kararnab/authdemo/pkg/iam/...` becomes `github.com/kararnab/iam/...`.
   The `pkg/` prefix is dropped.
2. `service.New(service.Options)` becomes `iam.New(iam.Config)`. The `service` package is removed.
   `Options.SessionManager` and `SessionStore` are replaced by `Config.Sessions` (a `session.Store`).
3. `iam.Service`: `Authenticate` becomes `Login` and returns `LoginResult` (session token, or access plus
   refresh token, depending on the mode). `Refresh` takes `ClientInfo` and returns `*TokenPair`.
   `Revoke` becomes `Logout`. New methods are added, so other implementations of the interface stop
   compiling.
4. `Subject.ID` is now the canonical internal ID, not the provider ID. Tokens issued before the change
   no longer map to the same subject.
5. `provider.Identity.Roles` is removed, and `EmailVerified bool` is added.
6. `provider/inhouse` becomes `provider/password`. `inhouse.User` and `inhouse.UserStore` are replaced by
   `password.CredentialStore` plus `IdentityStore`, and the provider name `internal` becomes `password`.
7. `provider/google` is removed and replaced by `oidc.NewGoogle` in the sub-module. The name
   `generic-oidc` becomes a configurable name.
8. `session.Session`, `session.Manager` and `session.Store` are redesigned: there is a public ID
   separate from the secret, hashed storage, families and rotation. Previously stored sessions are
   invalid. They were in memory only, so nothing persistent is lost.
9. `policy.DefaultPolicy` and `policy.Admin` are removed. The default is deny, and `iam.New` fails
   without an engine. `policy.ResourceContext` is renamed `policy.Resource`.
10. `token.Claims` gains `SessionID`, `Audience`, `IssuedAt`, `ExpiresAt` and `ID`.
    `token.MultiVerifier` and `token.SingleVerifier` are removed.
    `jwt.NewIssuer` and `jwt.NewVerifier` take a `keys.Provider` and a `jwt.Config` with issuer,
    audience and leeway. `keys.Key` gains `Alg`. HMAC keys shorter than 32 bytes are rejected.
11. PASETO moves from `v2.local` to `v4.local`/`v4.public` in the `paseto` sub-module. Existing tokens
    become invalid (they expire within 15 minutes anyway).
12. `audit` event constants are renamed and extended, and `audit.Event` gains fields. `audit/stdout` is
    replaced by `audit.SlogLogger`.
13. `metrics.IAMMetrics` becomes `metrics.Recorder`. Prometheus moves to its own sub-module, and metric
    names change from `authdemo_iam_*` to `iam_*`, so dashboards must be updated.
14. `pkg/log`, `pkg/secret_store` and `pkg/metrics` are no longer part of any importable API.
15. Minimum Go version: 1.25 becomes 1.26.
16. **Demo HTTP API:**
    - `/api/register` requires an invite.
    - Responses use snake_case JSON.
    - `/api/refresh` returns a new refresh token, and a reused refresh token gets `401` and revokes the
      session.
    - Cookie-mode endpoints are added: `/api/session/login`, `/logout` and `/csrf`.
    - `/api/sessions` (list, revoke, revoke-all) is added.
    - `/api/invites` is added (admin only).
    - Book writes require the `books:write` permission.
    - `/admin/keys/rotate` no longer returns key material.
    - `/metrics` binds to a separate admin port.
    - The demo refuses to start without `IAM_SIGNING_KEY` unless `-dev` is set.

---

## 5. Phases

Every phase ends with `go vet`, `go test -race` across all modules, and one commit on
`feature/reusable-iam`. Nothing is pushed or tagged without your approval.

| Phase | Content | Fixes |
|---|---|---|
| P0 | Hygiene: remove `.env`, add `.env.example`, update `.gitignore`, commit this plan. | F3 |
| P1 | Restructure into the root module and `examples/demo`. Move `pkg/iam/*` to the root. Move `cmd/server` and `internal` into the demo. Remove chi, uuid and zerolog. Add the CI skeleton (vet, staticcheck, govulncheck, test -race, a matrix over the modules). Add characterization tests of the current flows first, so the move is checked. Fix the memory-store race. | F1, F10, F17 |
| P2 | Tokens: stdlib JWT with pinned alg, `kid` lookup, iss, aud, leeway and `typ`. A `keys.Provider` that the issuer reads on every issue. Fuzz tests for the JWT parser. | F8, F11, F15 |
| P3 | Subjects: `SubjectLoader`/`IdentityStore`/`CredentialStore`, canonical ID, identity linking, the `password` package (argon2id and bcrypt migration), the `password` provider with a dummy-hash path, and the `memstore` users. Fuzz tests for PHC parsing. | F5, F12 |
| P4 | Sessions: hashed storage, both modes, rotation and reuse detection with `ReuseGrace`, idle and absolute expiry, list and revoke, revoke-all. `Refresh` reloads the subject. Fuzz tests for refresh-token and cookie decoding. | F4, F6 |
| P5 | Policy: deny by default, RBAC, Chain, Func, audited denials. | F7 |
| P6 | Sign-up and invites, the rate limiter and lockout hooks, the full set of audit events, `metrics.Recorder`, and the nil-safe defaults. | F13, F14 |
| P7 | `httpauth`: middleware, cookie helpers, CSRF, context helpers. The demo is rewired onto the library and `httpauth`. End-to-end tests run both the cookie flow (invite, sign-up, login, CSRF, books, log out everywhere) and the bearer flow (login, refresh, reuse, revoked). Server timeouts and the admin port are added. | F2, F17, F18 |
| P8 | Sub-modules: `oidc` (issuer check, nonce, Google), `prometheus`, `paseto` v4, `pgstore` (with migrations and a CI Postgres service), `redisstore` (sessions and limiter, with a CI Redis service). | F9, F16 |
| P9 | Docs: README with a five-minute guide, one page per extension point (provider, store, policy, audit, metrics), SECURITY.md, the demo's OpenAPI spec, CHANGELOG (`v0.1.0`, unreleased), and a short scheduled fuzz job in CI. Then I ask you about tags `v0.1.0` and `<sub>/v0.1.0`. | — |

Tests in every package are table-driven, and every module runs `go test -race`. Fuzz targets: the JWT
compact parser, the session cookie decoder, the refresh and invite token decoder, and the PHC
password-hash parser.

---

## 6. Deliberately out of scope (listed as later work)

These are not in v0.1. They go into SECURITY.md under "what this library does not do":
- Acting as an identity provider or OAuth/OIDC server (authorize/token endpoints, client registration).
- MFA (TOTP), WebAuthn and passkeys, and step-up authentication.
- Helpers for the OIDC authorization-code flow with PKCE (planned for v0.2).
- Password reset and email verification. These can reuse the single-use token machinery from invites.
- Sending email or SMS. Invite tokens are returned to the caller.
- Publishing asymmetric keys as JWKS, DPoP and sender-constrained tokens, and device binding.
- Linking accounts automatically by verified email.
- Explicit deny rules in RBAC, policy versioning, ReBAC.
- Cluster-wide key distribution (`MemoryProvider` is single-process; KMS or Vault integration comes later).
