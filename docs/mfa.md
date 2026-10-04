# Multi-factor authentication (TOTP)

Time-based one-time passwords (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds),
which every authenticator app supports, plus single-use recovery codes.

```go
svc, _ := iam.New(iam.Config{
    // ...
    MFA: iam.MFAConfig{
        Store:  memstore.NewMFA(), // or pgstore.NewMFA(pool)
        Key:    mfaKey,            // >= 32 bytes, long-lived: seals TOTP secrets
        Issuer: "My App",          // shown in authenticator apps
    },
})
m := svc.(iam.MFA) // the Service returned by New implements it
```

| Setting | Default |
|---|---|
| `MFA.ChallengeTTL` | 5 minutes (max 15) to enter the code after the password |
| `MFA.Skew` | 1 step (30 s) either side of now (max 2) |
| `MFA.ExemptProviders` | none: every provider's logins ask for a code |

Without `MFA.Store`, nothing changes and the methods return
`iam.ErrMFANotConfigured`. `MFA` is a separate interface from
`iam.Service`, so adding it did not break code that implements `Service`.

## Enrollment

```go
e, err := m.BeginTOTPEnrollment(ctx, subject.ID, email) // e.URI → QR code, e.Secret → text
codes, err := m.ConfirmTOTPEnrollment(ctx, subject.ID, codeFromApp)
// Show codes once: ten "xxxxx-xxxxx" recovery codes.
```

A factor is pending until confirmed, and pending factors do not affect
login. `BeginTOTPEnrollment` on a confirmed factor gives
`ErrMFAAlreadyEnrolled`. `DisableTOTP`, `RegenerateRecoveryCodes` and
`TOTPEnabled` complete the set. Authorize these calls yourself (the subject,
signed in); before `DisableTOTP`, ask for a fresh code with `VerifyMFA`.

## Login

Once a subject has a confirmed factor, a correct password no longer starts
a session. `Login` returns `*iam.MFARequiredError` (wrapping
`iam.ErrMFARequired`), so code that does not know about MFA **fails
closed**:

```go
res, err := svc.Login(ctx, req)
var need *iam.MFARequiredError
if errors.As(err, &need) {
    // 401 {"mfa_required": true, "challenge": need.Challenge}
}

// Then, with the code the user typed (or a recovery code):
res, err = m.CompleteMFA(ctx, iam.MFARequest{Challenge: challenge, Code: code, Client: auth.ClientInfo(r)})
auth.StartSession(w, res) // res.Session.MFA is true
```

- The challenge is sealed (AES-GCM, from `MFA.Key`) and holds the subject,
  session mode and provider, with a short expiry. It is useless without a
  valid code.
- **Codes cannot be replayed:** a TOTP code is accepted only for a time step
  later than the last one used (`Store.AdvanceTOTP` is atomic). Recovery
  codes are single-use (`Store.UseRecoveryCode` is atomic) and stored as
  hashes; case, spaces and dashes do not matter when typed.
- **Wrong codes are throttled** per subject with the per-login limiter
  (`RateLimit.PerLogin`, key `mfa:<subject>`). While throttled, even the
  right code is refused (`*RateLimitError`).
- Disabled subjects cannot complete a challenge.
- `ExemptProviders` skips the second factor for providers that enforce
  their own, such as a corporate OIDC issuer.
- Password reset does not bypass MFA: the next login still asks for a code.

## Step-up and marking sessions

- `m.VerifyMFA(ctx, subjectID, code, client)` checks a code for a signed-in
  subject, before a sensitive action. It is throttled and replay-protected
  like login.
- Sessions started through `CompleteMFA` have `SessionInfo.MFA` set (and
  keep it through `RotateSession`). `httpauth.Middleware.RequireMFA` rejects
  other sessions with 403. Bearer access tokens do not carry the flag; for
  bearer requests it is known only with `Config.VerifySessionOnAccess`.

## Secrets at rest

The raw TOTP secret is shown once, at enrollment. IAM seals it with a key
derived from `MFA.Key` (AES-GCM, bound to the subject ID) before it reaches
the store, so a database leak does not reveal it, and a sealed secret
copied to another subject does not open. Changing `MFA.Key` makes every
enrolled factor unusable: users would need recovery codes or an
administrator's `DisableTOTP`.

## Stores

`mfa.Store`: one factor per subject; `AdvanceTOTP` and `UseRecoveryCode`
must be atomic. `memstore.MFA` and `pgstore.MFA` (table `iam_mfa_totp`,
migration 0003) implement it, and `storetest.MFA` is the conformance suite.

## Events

Audit: `mfa_challenge`, `mfa_success`, `mfa_failure` (`reason`),
`mfa_enrolled`, `mfa_disabled`, `mfa_recovery_code_used` (`remaining`),
`mfa_recovery_codes_issued`; a completed MFA login also logs
`login_success` with `mfa`. Metrics: `mfa_challenge`, `mfa_success`,
`mfa_failure`.
