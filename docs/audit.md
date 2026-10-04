# Audit

IAM reports security-relevant events to an `audit.Logger`:

```go
type Logger interface {
    Log(ctx context.Context, event audit.Event) error
}

type Event struct {
    Time      time.Time
    Type      EventType
    SubjectID string            // canonical subject, if known
    SessionID string            // public session ID, never the secret
    Provider  string
    ClientIP  string
    Message   string
    Attrs     map[string]string // reason, count, invite_id, ...
}
```

The default is `audit.SlogLogger`, which writes to `slog.Default()`. Events
never contain passwords, tokens or session secrets.

## Events

| Type | When | Notable attrs |
|---|---|---|
| `login_success` | login completed | `mode` |
| `login_failure` | login rejected | `reason`: `invalid_credentials`, `unknown_identity`, `subject_disabled`, `rate_limited`, ... |
| `logout` | session ended by its holder | |
| `refresh_success` / `refresh_failure` | refresh-token use | `reason` |
| `refresh_reuse_detected` | a rotated refresh token was replayed; **session revoked** (logged at WARN) | |
| `session_rotated` | cookie session token replaced | |
| `session_revoked` | one session revoked by ID | |
| `sessions_revoked_all` | "log out everywhere" | `count` |
| `token_verify_failure` | invalid access token | |
| `policy_denied` | authorization denied | `action`, `resource_type`, `resource_id`, `reason` |
| `identity_linked` | identity linked to a subject | |
| `signup` | sign-up succeeded or failed | `invite_id` or `reason` |
| `invite_created` / `invite_consumed` | invite lifecycle | `invite_id`, `roles`, `invited_by` |
| `rate_limited` | attempt refused while throttled | `scope`: `login`, `ip`, `reset_login` or `reset_ip` |
| `lockout` | a key just became throttled (logged at WARN) | `scope`, `failures`, `retry_after` |
| `password_reset_requested` | a reset was requested (issued or not) | `reason` when not issued: `unknown_login`, `subject_disabled`, `rate_limited`, ... |
| `password_reset` | a reset completed or failed | `token_id`, `sessions_revoked`, or `reason` |
| `email_verification_requested` / `email_verified` | verification lifecycle | `token_id`, or `reason` on failure |

Alert on `refresh_reuse_detected` and on bursts of `lockout`.

## Sinks

```go
cfg.Audit = audit.Multi(
    audit.NewSlogLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil))),
    audit.Func(func(ctx context.Context, e audit.Event) error {
        return siem.Send(ctx, e) // your sink
    }),
)
```

`Log` runs synchronously on the request path. Buffer inside slow sinks, for
example with a channel and a worker. Errors from `Log` are ignored by IAM
and never fail a login, so make sure your sink reports its own failures.
