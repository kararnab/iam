# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

Each module is tagged separately and the versions move together: `v2.1.0`
for the core module, and `oidc/v2.1.0`, `paseto/v2.1.0`, `pgstore/v2.1.0`,
`redisstore/v2.1.0` and `prometheus/v2.1.0` for the sub-modules.

## [Unreleased]

### Added

- `pgstore.SessionMigrations` and `pgstore.MigrateSessions`: only the session
  and invite tables (`iam_sessions`, `iam_rotated_tokens`, `iam_invites`),
  for applications that implement `iam.UserStore` over their own tables.
  `pgstore.UserMigrations` and `pgstore.MigrateUsers` hold the user tables.
  Each partial set has its own tracker table; mixing a partial set with
  `Migrate` on one database returns `pgstore.ErrMigrationSetConflict`
  ([#8](https://github.com/kararnab/iam/issues/8)).
- **Password reset and email verification** ([#12](https://github.com/kararnab/iam/issues/12),
  [docs](docs/recovery.md)): `iam.Recovery` (`StartPasswordReset`,
  `CompletePasswordReset`, `StartEmailVerification`,
  `CompleteEmailVerification`), implemented by the Service from `New` and
  enabled by `Config.Recovery`. Reset requests reveal nothing about which
  logins exist and are throttled; completing a reset revokes every session.
  New package `onetime` (tokens and `Store`), `memstore.Tokens`,
  `pgstore.Tokens`, `storetest.Tokens`, `provider.PasswordSetter`
  (implemented by the password provider), and audit and metric events for
  both flows. The demo app has both flows, with end-to-end tests.
- **OIDC authorization-code flow** ([#11](https://github.com/kararnab/iam/issues/11),
  [docs](docs/providers.md#signing-in-with-a-redirect-oidccodeflow)):
  `oidc.CodeFlow` (`NewCodeFlow`, `Start`, `Redirect`, `Callback`) with
  PKCE S256, state and nonce kept in an AES-GCM-encrypted `__Host-` cookie
  (no server-side store), an RFC 9207 issuer check, and local-path-only
  return addresses. `Callback` returns the params for `Service.Login`,
  `SignUp` or `LinkIdentity`. The `oidc` module now requires
  `golang.org/x/oauth2` directly (it was already indirect).
- **JWKS for EdDSA access tokens** ([#15](https://github.com/kararnab/iam/issues/15),
  [docs](docs/tokens.md#publishing-keys-jwks)): `jwt.PublicJWKS` and
  `jwt.JWKSHandler` publish the Ed25519 public keys of a `keys.Provider`
  (never HS256 secrets); `jwt.NewRemoteKeys` is a verification-only provider
  over a remote set, with background refresh and rate-limited fetches on
  unknown key IDs. `keys.Finder` lets a provider look keys up itself;
  `keys.Find` prefers it.
- `docs/stores.md`: using `pgstore` from a `database/sql` application (one
  pgx pool with `stdlib.OpenDBFromPool`, or a second small pool).

### Schema changes

From this release on, every entry that changes the `pgstore` schema names
the tables it touches, so applications that copy the SQL know when to act.

- `pgstore` migration 0002 adds **`iam_one_time_tokens`** (password-reset
  and verification tokens). It is in `Migrations` and in
  `SessionMigrations`; no existing table changes.

## [2.1.0] — 2026-10-03

The sub-modules have no changes of their own; they are released together
with the core module and require core `v2.1.0`.

### Added

- `iam.ErrUnavailable`: wraps a store failure while checking a session or
  a subject, so callers can answer "try again" instead of "signed out".
  `httpauth.ErrUnavailable` wraps it.
- `storetest.UsersWith` and `storetest.UsersOptions`, for user stores that
  allow one role per subject or require a role.
- `session.Manager.Inspect`: checks a refresh token without rotating it.

### Changed

- `httpauth.Middleware.Protect` answers **503** (`ErrUnavailable` to the
  `ErrorHandler`) when a store fails while it checks a cookie or bearer
  credential. Before, the request silently became anonymous, so a signed-in
  user looked signed out during an outage. Invalid credentials are still
  anonymous.
- `ValidateSession`, `RotateSession`, `Refresh`, `Logout` and
  `VerifyAccessToken` (with `VerifySessionOnAccess`) return errors wrapping
  `ErrUnavailable` for store failures, instead of passing the raw error or
  reporting `ErrInvalidSession`.
- `storetest.Users` creates its second subject from a different identity
  and email, so stores with unique emails can run it.
- `Refresh` loads the subject **before** rotating the refresh token.
- CI lints every module with golangci-lint (`.golangci.yml`: the standard
  set plus gosec, errorlint, gocritic, bodyclose, nilerr, misspell,
  unconvert, copyloopvar; gofmt and goimports). It replaces the separate
  gofmt and staticcheck steps.
- The quickstart example sets server timeouts.
- README: replaced the Go Report Card badge (service shut down) with a
  Go version badge.

### Fixed

- `ValidateSession`, `RotateSession` and `Refresh` revoked the session when
  loading the subject failed for any reason, so a transient database error
  signed the user out. They now revoke only when the subject is gone or
  disabled.
- `RotateSession` rotated the secret before loading the subject, so a failure
  there discarded the client's only valid secret. It now checks the subject
  first.
- `Refresh` rotated the refresh token before loading the subject, so a
  transient failure there lost the new token, and the client's retry with
  the old one revoked the whole session as reuse (#7).
- pgstore: the deferred rollback in `Migrate` no longer drops its error
  unchecked.

## [2.0.0] — 2026-10-02

First release as a reusable library, extracted from the AuthSystemDemo
application (`github.com/kararnab/authdemo/pkg/iam`). Numbering starts at 2
because the repository's earlier tags (`v1.0-nodejs`, `v1.1-golang`) belong
to the demo application. Module paths therefore end in `/v2`, as Go
requires for major versions above 1.

### Added

- Importable module `github.com/kararnab/iam/v2` whose only dependency is
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
  `github.com/kararnab/iam/v2/...`, and sub-modules
  `github.com/kararnab/iam/<module>/v2`.
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

[Unreleased]: https://github.com/kararnab/iam/compare/v2.1.0...HEAD
[2.1.0]: https://github.com/kararnab/iam/releases/tag/v2.1.0
[2.0.0]: https://github.com/kararnab/iam/releases/tag/v2.0.0
