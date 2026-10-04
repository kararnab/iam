# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's **Security →
Report a vulnerability** (private security advisories) on this repository.
Don't open public issues for them. Include a description, affected
versions, and a reproduction if you have one.

Security fixes go into the latest v2 release.

## Threat model

### What we protect

- user credentials (passwords) and the identities linked to subjects;
- session secrets (cookie values) and refresh tokens;
- access-token signing keys;
- authorization decisions;
- the integrity of the audit trail IAM emits.

### Attackers we defend against

| Attacker | Defences |
|---|---|
| **Password guessing and credential stuffing** | Throttling per login and per IP with growing back-off (`ratelimit`); throttled attempts never reach the password hasher; argon2id hashing; length policy (≥ 12 characters). |
| **User enumeration** | Unknown logins cost the same hash verification as known ones; login errors don't say which part was wrong; throttling counts unknown and known logins alike. |
| **Stolen database or backup** | Only SHA-256 hashes of session secrets, refresh tokens and invite tokens are stored, so a dump contains no usable credentials. Passwords are argon2id (bcrypt hashes are upgraded on login). |
| **Stolen refresh token** | Refresh tokens rotate on every use. Replaying a rotated token revokes the whole session (`refresh_reuse_detected`, logged at WARN), which locks out both the attacker and the victim until they log in again. |
| **Stolen access token** | Short lifetime (10 minutes by default); optional per-request session check (`VerifySessionOnAccess`) for immediate revocation. |
| **Token forgery and algorithm confusion** | Each key is pinned to one algorithm; the key is chosen by `kid`; `none`, RSA and ECDSA are rejected; HS256 keys must be ≥ 32 bytes; `iss`, `aud`, `exp`, `nbf`, `iat` are checked with bounded leeway; `typ: at+jwt` stops ID tokens being used as access tokens; strict canonical decoding (fuzzed). |
| **Forged or misdirected ID tokens (OIDC)** | Issuer checked against an explicit list, audience must be your client ID, signature from the issuer's published keys, optional nonce. |
| **Cross-site request forgery** | `SameSite=Lax` cookies; `http.CrossOriginProtection` (Fetch Metadata and `Origin`) on every unsafe request, including login; a per-session HMAC CSRF token for cookie-authenticated unsafe requests; constant-time comparison. |
| **Session fixation and cookie tossing** | A fresh session ID at every login; `RotateSession` for privilege changes; `__Host-` cookie prefix (Secure, Path=/, no Domain); duplicate session cookies make a request anonymous. |
| **Session hijacking via script** | `HttpOnly` cookies keep the secret out of reach of JavaScript. (XSS can still act as the user while the page is open; see below.) |
| **Privilege escalation through policy gaps** | Deny by default; `iam.New` refuses to start without a policy engine; engine errors deny; every denial is audited. |
| **Account takeover through identity linking** | No automatic linking by email; linking requires an authenticated subject and fails if the identity belongs to someone else. |
| **Invite abuse** | Invites are 256-bit, single-use (atomic consumption), expiring, optionally bound to an email, and grant only the roles the inviter chose. |
| **Spoofed client IPs** | `X-Forwarded-For` is only believed from configured trusted proxies. |
| **Timing side channels** | HMAC, CSRF token, nonce and password comparisons are constant-time; secrets are looked up by hash, never compared byte-by-byte against attacker input. |

### Out of scope

- **Transport security.** Terminate TLS in front of your application. Without
  it, every cookie and token can be stolen in transit.
- **Cross-site scripting.** `HttpOnly` prevents theft of the session
  secret, but script running in your origin can make requests as the user.
  Use output encoding, a Content Security Policy and framework escaping.
- **Compromised servers or databases with write access.** An attacker who
  can write to your stores can grant themselves roles.
- **Denial of service** beyond login throttling and bounded request
  parsing. Put rate limits and request size limits at your edge as well.
- **Hard lockout.** Throttling slows guessing without letting anyone lock a
  user out. If you need hard lockout, implement it in `LockoutHooks`.

## Defaults

| Setting | Default |
|---|---|
| Session mode | cookie only (`AllowedModes`) |
| Cookie | `__Host-session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` |
| Cookie session timeouts | 30 minutes idle, 7 days absolute |
| Bearer session timeouts | 14 days idle, 30 days absolute |
| Access-token lifetime | 10 minutes, leeway 30 seconds (max 2 minutes) |
| Refresh-token reuse grace | 0 (any reuse revokes) |
| Session secrets, refresh, invite, reset and verification tokens | 256 bits from `crypto/rand`, stored as SHA-256 |
| Password reset | off until `Recovery.Tokens` is set; tokens expire after 1 hour, requests are throttled, completion revokes every session |
| Email verification | off until `Recovery.Tokens` is set; tokens expire after 48 hours |
| MFA (TOTP) | off until `MFA.Store` is set; then required at login for subjects who enrolled; codes ±30 s, never replayable; 5-minute challenges; wrong codes throttled per subject; secrets sealed with AES-GCM |
| Password hashing | argon2id, m=19 MiB, t=2, p=1, concurrency = GOMAXPROCS |
| Password length | 12–1024 |
| Login throttling | on: in-memory, 5 failures per login and 100 per IP within 15 minutes, then back-off from 1s doubling to 15 minutes (`RateLimit.Disabled` turns it off) |
| Sign-up | closed; invite-only once an invite store is set; invites expire after 7 days |
| Authorization | none until you configure an engine; nothing allowed implicitly |
| CSRF | on: cross-origin protection plus a token for cookie sessions |
| `X-Forwarded-For` | ignored unless `TrustedProxies` is set |
| OIDC code flow | PKCE S256, state and nonce always; flow cookie AES-GCM, `__Host-`, `HttpOnly`, `SameSite=Lax`, 10 minutes; `returnTo` local paths only |

## What the library deliberately does not do

- It is **not an OAuth 2.0 authorization server or OpenID provider**: no
  `/authorize` or `/token` endpoints, no client registration, no consent.
- **No WebAuthn or passkeys** yet (TOTP multi-factor authentication is
  supported).
- **It sends no email.** Invite, password-reset and verification tokens are
  returned to your code to deliver.
- **No automatic account linking** by email.
- **No DPoP or sender-constrained tokens.**
- **No distributed key management.** `keys.MemoryProvider` is
  single-process; back `keys.Provider` with your KMS or Vault.
- **No storage of your user profile data** beyond subjects, roles and
  identities in the optional stores.

## Running it safely

- Serve over HTTPS. Never set `CookieConfig.Insecure` outside local
  development.
- Generate keys with a CSPRNG (`openssl rand -base64 32`), keep them out of
  source control, and rotate them (`keys.MemoryProvider.Rotate`, then
  `Prune` after one token lifetime).
- With more than one instance, share the stores (PostgreSQL or Redis), the
  rate limiter (`redisstore.Limiter`), the signing keys, and the CSRF key
  (`CSRFConfig.Key`).
- Configure `TrustedProxies` to match your load balancers.
- Alert on `refresh_reuse_detected` and on bursts of `lockout` and
  `login_failure`.
- Run `pgstore.(*Sessions).PurgeExpired` periodically.
- Keep dependencies current; CI runs `govulncheck`.
