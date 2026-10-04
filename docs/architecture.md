# Architecture

`iam` is a thin, modular layer between an application and its identity
providers. It is **not** an identity provider like Keycloak, and it does not
hold the application's user data model.

## Responsibilities

IAM owns authentication and authorization infrastructure:

- **Authentication:** delegates credential checks to pluggable providers and
  maps the external identity to the application's canonical subject.
- **Sessions:** server-side sessions in cookie or bearer mode, with hashed
  secrets, refresh-token rotation and reuse detection, listing and
  revocation.
- **Access tokens:** short-lived, format-agnostic (JWT or PASETO), with
  rotation-safe keys.
- **Sign-up:** closed, invite-only or open.
- **Authorization:** asks a policy engine; denies by default.
- **Abuse resistance:** throttles failed logins per login and per IP.
- **Audit and metrics:** emits events without deciding where they go.

The application owns:

- users, roles and profile data (it implements `iam.UserStore`);
- business rules and domain entities;
- how sign-in is presented (pages, redirects, emails);
- where logs and metrics end up.

## Shape

```
Application
   │  (plain data in, plain data out)
   ▼
iam.Service ──────────────── implemented by iam.New (in-process),
   │                           or later by a remote client
   ├── provider.AuthProvider   password, oidc, yours
   ├── iam.UserStore           subjects + identities (application-owned)
   ├── session.Manager         over a session.Store
   ├── token.Issuer/Verifier   jwt, paseto, yours (keys.Provider)
   ├── policy.Engine           RBAC, AnyOf/AllOf, yours
   ├── invite.Store            sign-up invites
   ├── ratelimit.Limiter       failed-login throttling
   ├── audit.Logger            security events
   └── metrics.Recorder        counters

httpauth.Middleware ── net/http adapter that depends ONLY on iam.Service
```

## Package layout

```
github.com/kararnab/iam/v2         Service, Config, New, Subject, store contracts
├── provider/                      AuthProvider, Identity, Registrar, PasswordSetter
├── password/                      argon2id/bcrypt Hasher, Policy, password Provider
├── session/                       Session, Store, Manager (rotation, reuse detection)
├── token/                         Issuer, Verifier, Claims
│   ├── jwt/                       stdlib JWS: HS256, EdDSA
│   └── keys/                      Key, Provider, MemoryProvider
├── policy/                        Engine, RBAC, Func, AnyOf, AllOf, DenyAll
├── invite/                        Invite, Store, Policy
├── onetime/                       password-reset and verification tokens
├── ratelimit/                     Limiter, LockoutHooks, Memory
├── audit/                         Logger, Event, SlogLogger, Multi
├── metrics/                       Recorder, Noop
├── httpauth/                      net/http middleware, cookies, CSRF
├── memstore/                      in-memory reference stores
├── storetest/                     store conformance suite
├── examples/quickstart/           the README's five-minute guide
│
├── oidc/        (module)          OpenID Connect and Google
├── paseto/      (module)          PASETO v4 tokens
├── pgstore/     (module)          PostgreSQL stores + migrations
├── redisstore/  (module)          Redis sessions + limiter
├── prometheus/  (module)          Prometheus recorder
└── examples/demo/ (module)        demo app, imports everything like a consumer
```

## Design principles

- **Provider-agnostic.** IAM does not care how someone authenticated, only
  that a provider vouched for a stable identity.
- **Token-format agnostic.** JWT, PASETO or opaque tokens can be swapped
  without touching application code.
- **No business logic.** Roles mean nothing to IAM; the policy engine
  interprets them.
- **No HTTP inside the core service.** `iam.Service` takes and returns plain
  data. HTTP lives in `httpauth`, which depends only on the interface.
- **Replaceable as a remote service.** Because of the two points above, a
  gRPC or HTTP client can implement `iam.Service` without changes to
  callers.
- **Small dependency surface.** The core module uses the standard library
  and `golang.org/x/crypto` only. Everything else is an opt-in module.
- **Secure by default.** Deny by default, hashed secrets, rotation with
  reuse detection, pinned algorithms, CSRF protection, throttling. See
  [SECURITY.md](../SECURITY.md).

## Flows

**Login.** `Service.Login` → rate-limit check → `provider.Authenticate` →
`IdentityStore.ResolveIdentity` → `SubjectLoader.LoadSubject` (rejects
disabled subjects) → `session.Manager.Create` → in bearer mode,
`token.Issuer.Issue` → audit `login_success`.

**Cookie request.** `httpauth.Protect` → cross-origin check → read the
cookie → `Service.ValidateSession` (loads the subject, so role changes apply
immediately) → CSRF token check for unsafe methods → handler →
`RequirePermission` → `Service.Authorize` → `policy.Engine`.

**Bearer request.** `httpauth.Protect` → `Service.VerifyAccessToken`
(stateless, or session-checked with `VerifySessionOnAccess`) → handler.

**Refresh.** `Service.Refresh` → `session.Manager.Refresh` (atomic rotation;
a reused token revokes the session) → reload the subject → issue a new
access token.

**OIDC redirect sign-in.** `oidc.CodeFlow.Start` (encrypted state cookie,
PKCE challenge, nonce) → the provider → `CodeFlow.Callback` (state and
issuer check, code exchange with the verifier) → `Service.Login` with the
ID token and the cookie's nonce.

**Sign-up.** `Service.SignUp` → check the invite → register or authenticate
the identity → consume the invite atomically → `CreateSubject` +
`LinkIdentity` → start a session. Any failure after registration rolls the
registration back.
