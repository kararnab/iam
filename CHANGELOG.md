# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before v1.0.0, minor versions may
contain breaking changes.

Each module is tagged separately: `v0.1.0` for the core module, and
`oidc/v0.1.0`, `paseto/v0.1.0`, `pgstore/v0.1.0`, `redisstore/v0.1.0` and
`prometheus/v0.1.0` for the sub-modules.

## [Unreleased] — planned as v0.1.0

First release as a reusable library, extracted from the AuthSystemDemo
application (`github.com/kararnab/authdemo/pkg/iam`).

### Added

- Importable module `github.com/kararnab/iam` whose only dependency is
  `golang.org/x/crypto`. Optional modules: `oidc`, `paseto`, `pgstore`,
  `redisstore`, `prometheus`.
- Two session modes: HttpOnly cookie sessions (default) and bearer access
  tokens with rotating refresh tokens. One service can allow both.
- Refresh-token rotation with reuse detection: replaying a rotated token
  revokes the session. Optional grace window for concurrent refreshes.
- Session listing and revocation per subject, and "log out everywhere
  (else)".
- Canonical subject IDs and identity linking (`IdentityStore`,
  `Service.LinkIdentity`): one subject, many provider identities.
- `password`: argon2id hashing (PHC format, configurable, bounded
  concurrency), bcrypt verification with transparent upgrade, length policy,
  and a username/password provider.
- Invite-only sign-up with single-use, expiring, optionally email-bound
  invites, switchable to open or closed (`Service.SignUp`, `CreateInvite`,
  `RevokeInvite`).
- Login throttling per login and per IP with growing back-off, on by
  default, plus `LockoutHooks`.
- `policy.RBAC`, `policy.AnyOf`, `policy.AllOf`, `policy.Func`,
  `policy.DenyAll`.
- `httpauth`: standard-library middleware with authentication (cookie or
  bearer), `RequireAuth`, `RequireRole`, `RequirePermission`, CSRF and
  cross-origin protection, cookie helpers, context helpers, and
  trusted-proxy client IPs.
- Standard-library JWT (`token/jwt`): HS256 and EdDSA, pinned algorithm per
  key, `kid` lookup, issuer, audience and leeway, `typ: at+jwt`.
- Audit event set covering logins, logouts, refreshes, reuse detection,
  revocations, denials, sign-ups, invites and throttling; `audit.SlogLogger`,
  `audit.Multi`.
- `metrics.Recorder` with a fixed event set; Prometheus
  `iam_events_total{event}`.
- Stores: `memstore` (in memory), `pgstore` (PostgreSQL, with embedded
  migrations and `Migrate`), `redisstore` (sessions and a shared rate
  limiter), and the `storetest` conformance suite.
- OIDC provider for any issuer and for Google, with nonce support.
- PASETO v4 (`v4.local`, `v4.public`).
- Documentation: README with a five-minute guide, one page per extension
  point, SECURITY.md, and an OpenAPI spec for the demo.
- CI on Go 1.26 and 1.27: vet, gofmt, staticcheck, govulncheck,
  `go test -race`, integration tests on PostgreSQL and Redis, and weekly
  fuzzing.

### Changed (breaking, relative to `authdemo/pkg/iam`)

- Module path `github.com/kararnab/authdemo/pkg/iam/...` became
  `github.com/kararnab/iam/...`.
- `service.New(service.Options)` became `iam.New(iam.Config)`; the `service`
  package is gone.
- `iam.Service`: `Authenticate` became `Login` (returns `LoginResult`),
  `Refresh` returns a rotated `TokenPair`, `Revoke` became `Logout`, and
  `VerifyAccessToken` also returns the session. New methods:
  `ValidateSession`, `RotateSession`, `ListSessions`, `RevokeSession`,
  `RevokeAllSessions`, `LinkIdentity`, `SignUp`, `CreateInvite`,
  `RevokeInvite`.
- `Subject.ID` is the application's canonical ID, not the provider's.
  Roles come only from the application's store.
- `provider.Identity.Roles` removed; `EmailVerified` added.
- `provider/inhouse` became `password.Provider`; the provider name
  `internal` became `password`.
- `session` package redesigned: public ID separate from the secret, hashed
  storage, `Store` with atomic `Rotate`, concrete `Manager`.
- `policy.ResourceContext` renamed `policy.Resource`. A policy engine is
  now required.
- `token.Claims` gained session, ID, issuer, audience and time fields.
  `jwt.NewIssuer` and `jwt.NewVerifier` take a `keys.Provider` and a
  `jwt.Config`. `keys.Key` gained `Alg`, `Secret`, `PrivateKey` and
  `PublicKey`. `MemoryProvider.Rotate` returns an error.
- PASETO moved from v2.local to v4 in its own module.
- Audit event names changed (for example `auth_success` became
  `login_success`), and `audit.Event` gained fields.
- `metrics.IAMMetrics` replaced by `metrics.Recorder`; Prometheus metric
  names changed from `authdemo_iam_*` to `iam_events_total{event}`.
- Minimum Go version raised to 1.26.

### Removed

- `policy.DefaultPolicy` (allowed every resource type except `admin`).
- `token.MultiVerifier`, `token.SingleVerifier`.
- `audit/stdout` and `pkg/log` (zerolog); use `audit.SlogLogger` and
  `log/slog`.
- `provider/google` (use `oidc.NewGoogle`); the `google.golang.org/api`
  dependency.
- `pkg/secret_store` (moved into the demo; the hard-coded secret store is
  gone).

### Fixed

- `Refresh` issued access tokens without roles or attributes.
- Session secrets and refresh tokens were stored in plain text.
- The JWT verifier accepted any HMAC algorithm, did not check the audience,
  and accepted empty subjects; short HMAC keys were allowed.
- Rotating signing keys had no effect: the issuer kept the startup key.
- The OIDC provider skipped the issuer check.
- Data race in the in-memory session store (map write under a read lock).
- Login timing revealed whether a username existed.
- A nil metrics implementation panicked.
- JWT and PHC hash decoding accepted non-canonical encodings (found by
  fuzzing).

### Security

- The demo no longer signs tokens with a hard-coded key or seeds a known
  admin password unless started with `-dev`. **Rotate any secret that was
  ever committed**: `.env` (`JWT_SECRET_KEY`) was tracked in git history
  before this release.
