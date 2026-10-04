# Password reset and email verification

Both flows use single-use, expiring tokens (package `onetime`): 256 random
bits handed to your code once, stored only as a SHA-256 hash, consumed
atomically. IAM **sends no email**: the `Start` methods return the token,
and you deliver it, typically as a link.

```go
svc, _ := iam.New(iam.Config{
    // ...
    Recovery: iam.RecoveryConfig{Tokens: memstore.NewTokens()}, // or pgstore.NewTokens(pool)
})
rec := svc.(iam.Recovery) // the Service returned by New implements it
```

| Setting | Default |
|---|---|
| `Recovery.PasswordProvider` | `"password"` (must implement `provider.PasswordSetter`) |
| `Recovery.ResetTTL` | 1 hour (max 24 hours) |
| `Recovery.VerificationTTL` | 48 hours (max 30 days) |

Without `Recovery.Tokens`, every method returns `iam.ErrRecoveryNotConfigured`.
`Recovery` is a separate interface from `iam.Service`, so adding it did not
break code that implements `Service`.

## Password reset

```go
// POST /password/forgot
issued, err := rec.StartPasswordReset(ctx, iam.PasswordResetRequest{
    Login: username, Client: auth.ClientInfo(r),
})
// err: *iam.RateLimitError (429) or iam.ErrUnavailable (503).
if issued != nil {
    go mailer.Send(emailOf(issued.SubjectID, issued.Login), resetLink(issued.Token))
}
// Answer 202 "if the account exists, we sent a link" in every case.

// POST /password/reset
subjectID, err := rec.CompletePasswordReset(ctx, iam.CompletePasswordResetRequest{
    Token: token, NewPassword: newPassword, Client: auth.ClientInfo(r),
})
```

- **No user enumeration.** For an unknown login, or a disabled subject,
  `StartPasswordReset` returns `(nil, nil)`. Respond the same way either way,
  and deliver the token outside the request so its timing does not differ.
- **Throttled** per login and per IP with the login limiters
  (`RateLimit.PerLogin`, `PerIP`), under separate keys: every request counts,
  and reset requests never lock anyone out of signing in.
- **A new request supersedes** the subject's earlier reset tokens.
- **The token is used up only when the new password passes the policy**, so
  a rejected password (`password.ErrTooShort`, `ErrTooLong`) can be fixed
  with the same link. A token for another purpose, an expired or used one,
  a disabled subject, or a login that now belongs to someone else all give
  `iam.ErrInvalidOneTimeToken`.
- On success, **every session of the subject is revoked** and the login's
  failed-login count is reset. Sign the user in again afterwards if you want.
- `IssuedToken` has no JSON encoding, so it cannot leak into a response by
  accident. Never return the token to the requester.

## Email verification

```go
// POST /email/verification (signed in)
issued, err := rec.StartEmailVerification(ctx, iam.EmailVerificationRequest{
    SubjectID: subject.ID, Email: email, Client: auth.ClientInfo(r),
})
// err: iam.ErrInvalidEmail (400), iam.ErrNotFound / ErrSubjectDisabled, ErrUnavailable.
go mailer.Send(issued.Email, verifyLink(issued.Token))

// GET or POST /email/verify
v, err := rec.CompleteEmailVerification(ctx, token, auth.ClientInfo(r))
// v.SubjectID, v.Email: record that this address is verified, in your user table.
```

You authorize `StartEmailVerification` (normally the subject itself). Users
are yours, so IAM returns the verified address and you store it. A new
request supersedes the subject's earlier verification tokens.

## Stores

`onetime.Store` has four methods; `Consume` must be atomic (one winner).
`memstore.Tokens` and `pgstore.Tokens` (table `iam_one_time_tokens`,
migration 0002) implement it, and `storetest.Tokens` is the conformance
suite. Run `(*pgstore.Tokens).PurgeExpired` periodically.

## Events

Audit: `password_reset_requested`, `password_reset`,
`email_verification_requested` and `email_verified`; failures carry a
`reason`. Metrics: `password_reset_requested`, `password_reset`,
`password_reset_failure`, `email_verified`, `email_verification_failure`.
