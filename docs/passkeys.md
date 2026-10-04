# Passkeys and security keys (WebAuthn)

The `webauthn` module adds WebAuthn sign-in as an ordinary identity
provider. Ceremonies are verified by
[go-webauthn](https://github.com/go-webauthn/webauthn); the core stays
dependency-free.

```sh
go get github.com/kararnab/iam/webauthn/v2
```

```go
pk, err := webauthn.New(webauthn.Config{
    RPID:          "example.com",                     // your registrable domain
    RPDisplayName: "Example",
    RPOrigins:     []string{"https://app.example.com"},
    Credentials:   memstore.NewPasskeys(),            // or pgstore.NewPasskeys(pool)
    Identities:    users,                             // the same store as iam.Config.Users
    Key:           stateKey,                          // >= 32 bytes, same on every instance
})
svc, _ := iam.New(iam.Config{
    Providers: []provider.AuthProvider{passwords, pk},
    // With TOTP configured, passkeys already prove two factors:
    MFA: iam.MFAConfig{ /* ... */ ExemptProviders: []string{pk.Name()}},
    // ...
})
```

## Model

Each credential is an **identity** of its subject: provider `"passkey"`,
provider ID = the base64url credential ID (`webauthn.ProviderID`). It is
linked through your `iam.IdentityStore`, so one subject can have a
password, a Google login and several passkeys. The credential itself
(public key, signature counter, flags, transports, a label) is kept in a
`passkey.Store`.

## Registering a passkey (signed in)

```go
// POST /passkeys/options
opts, state, err := pk.BeginRegistration(ctx, webauthn.User{SubjectID: s.ID, Name: email})
// → browser: navigator.credentials.create(PublicKeyCredential.parseCreationOptionsFromJSON(opts.publicKey))

// POST /passkeys
cred, err := pk.FinishRegistration(ctx, s.ID, state, credentialJSON, "MacBook")
```

- Resident keys and **user verification are required** (a passkey is
  possession plus PIN or biometrics); attestation is not requested.
- The subject's existing credentials are excluded, so one authenticator is
  not registered twice; a credential ID registered to anyone is refused.
- `FinishRegistration` checks that the state was issued for the same
  subject, so a state cannot be replayed into another account.
- `Credentials(ctx, subjectID)` lists them; `RemoveCredential` deletes one
  and unlinks its identity.

## Signing in

```go
// POST /passkeys/login/options (anonymous)
opts, state, err := pk.BeginLogin(ctx)
// → browser: navigator.credentials.get(...)

// POST /passkeys/login
res, err := svc.Login(ctx, iam.AuthRequest{
    Provider: pk.Name(),
    Params:   map[string]string{"state": state, "response": string(assertionJSON)},
    Client:   auth.ClientInfo(r),
})
```

Sign-in is username-less (discoverable credentials). `Authenticate`
checks the origin, RP ID, challenge, signature and user verification, that
the authenticator's user handle matches the credential's subject, and that
the signature counter did not go backwards (a cloned authenticator); then
it records the new counter and time. Failures wrap
`provider.ErrInvalidCredentials`, so `Login` throttles them per IP and
audits them like wrong passwords.

## Ceremony state

The challenge and its options are sealed (AES-GCM, key derived from
`Config.Key` and the provider name, bound to the ceremony kind) into the
opaque `state`, with a 5-minute expiry (`Timeout`, max 15 minutes). No
server-side store is needed, and any instance with the same key can finish
a ceremony. A login state cannot finish a registration and vice versa.

## Stores

`passkey.Store` (core package `passkey`): `Create` (`ErrConflict` on a
duplicate ID), `Get`, `ListBySubject`, `Touch`, `Delete`.
`memstore.Passkeys` and `pgstore.Passkeys` (table `iam_passkeys`,
migration 0004) implement it, and `storetest.Passkeys` is the conformance
suite. Only public keys are stored.

## Testing

The module's tests drive both ceremonies through `iam.Service.Login` with a
software authenticator (P-256, "none" attestation), and check every
rejection: wrong origin, foreign challenge, another subject's user handle,
a forged signature, an unknown credential, missing user verification, a
cloned counter, mixed-up and expired states.
