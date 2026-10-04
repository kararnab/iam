# Access tokens

Bearer-mode sessions issue short-lived access tokens through a
`token.Issuer` and check them with a `token.Verifier`. IAM is
format-agnostic; two formats ship with it.

| Format | Package | Algorithms | Dependencies |
|---|---|---|---|
| JWT (RFC 7519, `typ: at+jwt` per RFC 9068) | `token/jwt` (core) | `HS256`, `EdDSA` | stdlib only |
| PASETO v4 | module `iam/paseto` | `v4.local`, `v4.public` | `aidanwoods.dev/go-paseto` |

Claims: `iss`, `aud`, `sub` (canonical subject), `iat`, `nbf`, `exp`,
`jti`, `sid` (public session ID), `roles`, `attrs`.

## Keys and rotation

```go
kp := keys.NewMemoryProvider(keys.Key{ID: "2026-10", Alg: keys.HS256, Secret: secret})
issuer, _ := jwt.NewIssuer(kp, jwt.Config{Issuer: "my-app", Audience: "my-api"})
verifier, _ := jwt.NewVerifier(kp, jwt.Config{Issuer: "my-app", Audience: "my-api"})

// later
kp.Rotate(keys.Key{ID: "2026-11", Alg: keys.HS256, Secret: newSecret})
// ... once the old key's tokens have expired (TTL + leeway):
kp.Prune(0)
```

- Every key is **pinned to one algorithm**. The verifier finds the key by
  `kid` and requires the token's `alg` to match it, which rules out
  algorithm confusion. `none`, RSA and ECDSA are never accepted.
- The issuer reads the active key on every token, so rotation takes effect
  immediately.
- HS256 keys must be at least 32 bytes. Use `EdDSA` when other services
  should verify tokens without being able to mint them.
- `keys.Provider` is an interface: back it with your KMS or Vault.
  `MemoryProvider` is single-process.

## Publishing keys (JWKS)

With `EdDSA` keys, other services can verify your access tokens without
being able to mint them. Publish the public keys as a JSON Web Key Set:

```go
mux.Handle("GET /.well-known/jwks.json", jwt.JWKSHandler(kp, 5*time.Minute))
```

- Only Ed25519 public keys appear (`kty: OKP`, RFC 8037), active key first.
  HS256 secrets and private keys never do; an HS256-only provider serves an
  empty set.
- The set is built per request, so a rotation shows at once. `maxAge` sets
  `Cache-Control`; after rotating, keep the old key (do not `Prune`) for at
  least `maxAge` plus the access-token TTL.

On the verifying side, `jwt.RemoteKeys` is a verification-only
`keys.Provider` over that URL:

```go
remote, err := jwt.NewRemoteKeys(ctx, "https://auth.example/.well-known/jwks.json", jwt.RemoteKeysConfig{})
verifier, _ := jwt.NewVerifier(remote, jwt.Config{Issuer: "auth", Audience: "my-api"})
```

- It fetches once at start-up (and fails if it cannot), refreshes in the
  background every `RefreshInterval` (15 minutes), and fetches on an
  unknown `kid`, at most once per `MinRefreshInterval` (1 minute), so
  made-up key IDs cannot flood the issuer. A failed or empty fetch keeps the
  previous keys.
- Only `https` URLs (`AllowHTTP` is for tests), at most 64 KiB, and only
  Ed25519 signing keys are kept; every key stays pinned to `EdDSA`, so an
  HS256 token is rejected whatever its `kid`.
- `ActiveKey` is the zero key: `RemoteKeys` cannot issue tokens.
- Providers can look keys up themselves by implementing `keys.Finder`;
  `keys.Find` (used by both verifiers) prefers it.

## Verification

The JWT verifier rejects tokens:

- larger than 8 KiB, or containing characters outside base64url;
- with unknown header fields (`crit`, `jku`, embedded keys, ...) or a `typ`
  other than `at+jwt`;
- signed with an unknown `kid` or a different algorithm;
- with the wrong `iss` or `aud`, or an empty `sub`;
- past `exp`, before `nbf`, or issued in the future, with `Leeway`
  tolerance (default 30s, at most 2 minutes).

All failures wrap `token.ErrInvalidToken`; expiry additionally wraps
`token.ErrExpiredToken`.

## Revocation

Access tokens are stateless and live for `TTL` (10 minutes by default).
Revoking a session stops refreshes immediately, but an issued access token
stays valid until it expires. Set `iam.Config.VerifySessionOnAccess` to
check the session on every request (one store lookup) when revocation must
be immediate.

## Custom formats

Implement `token.Issuer` and `token.Verifier`, for example opaque tokens
backed by a store, or RS256 for interoperability. Return errors that wrap
`token.ErrInvalidToken`.
