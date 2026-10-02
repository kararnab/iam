# IAM (Identity & Access Management)

The `iam` package provides **authentication and authorization** infrastructure for the application.

It is not an identity provider like Google OAuth or Keycloak.
Instead, it acts as a **thin, modular IAM layer** that:
- integrates with one or more identity providers
- issues and verifies access tokens
- manages refresh-token–backed sessions
- enforces authorization policies
- emits audit events

The package is designed so it can later be:
- extracted into a standalone microservice, or
- replaced by a remote IAM service with minimal changes.

---

## What IAM is responsible for

IAM owns auth infrastructure, not application business logic.

Specifically, it handles:

- **Authentication** 
  - Delegates credential validation to pluggable providers 
  - Normalizes external identities into an internal Subject 
- **Session management**
  - Manages stateful refresh-token sessions 
  - Supports session revocation and rotation
  - Uses Redis-like storage abstractions
- **Access tokens**
  - Issues stateless access tokens (JWT / PASETO)
  - Verifies tokens using rotation-safe key management 
  - Hides token format from the rest of the app
- **Authorization**
  - Evaluates access decisions via a policy engine
  - Supports RBAC/ABAC-style decisions (extensible)
- **Audit logging**
  - Emits security-relevant events (auth success/failure, refresh, revoke)
  - Does not decide where logs are stored or sent

---

## What IAM explicitly does NOT do

IAM intentionally does not:
- Persist application user data (users belong to the app)
- Implement OAuth flows itself 
- Contain HTTP handlers or transport logic 
- Store business-domain entities 
- Decide logging backends or observability tooling

These concerns live outside IAM.

---

## High-level architecture

```java
Application
   |
   v
IAM Service (iam.Service)
   |
   +-- Providers        (Google, Keycloak, Internal, etc.)
   +-- Session Manager  (refresh tokens, stateful)
   +-- Token Issuer     (JWT / PASETO)
   +-- Token Verifier   (rotation-safe)
   +-- Policy Engine    (authorization decisions)
   +-- Audit Logger     (security events)

```

The application depends only on the `iam.Service` interface.

## Folder Structure

```graphql
iam/
├── auth.go          # Public IAM interface (Authenticate, Refresh, Verify, Revoke)
├── service/         # Default IAM service implementation
├── provider/        # Identity provider adapters (Google, internal, etc.)
├── session/         # Refresh-token session management (stateful)
├── token/           # Access token infrastructure (JWT / PASETO, key rotation)
├── policy/          # Authorization engine (RBAC/ABAC)
└── audit/           # Audit event contracts

```

Each subpackage has a single responsibility and can be replaced independently.

---

## Key design principles

- Provider-agnostic
    IAM does not care how a user authenticated—only that they did.

- Token-format agnostic
    JWT, PASETO, or opaque tokens can be swapped without touching application code.

- Separation of concerns
    Auth, sessions, tokens, policies, and audit logging are isolated.

- Security by default

    - Short-lived access tokens 
    - Stateful refresh tokens 
    - Key rotation support 
    - Centralized audit emission

- Microservice-ready
    - IAM is accessed via an interface 
    - Can be wrapped with HTTP/gRPC or replaced with a remote client

#### Note:
Tomorrow you can
`git subtree split pkg/iam → iam-service`
You won’t be rewriting logic — only wiring.

---

## Authentication and Authorization flows

### Typical authentication flow: 
1. Application calls iam.Service.Authenticate 
2. IAM delegates to the configured provider 
3. External identity is mapped to an internal Subject 
4. A refresh-token session is created 
5. An access token is issued 
6. Audit events are emitted

### Typical request authorization flow:
1. HTTP middleware extracts access token 
2. IAM verifies token and returns `Subject`
3. Policy engine evaluates access 
4. Application handler executes or rejects

---

## Summary

The `iam` package is auth support infrastructure:
- not a user database 
- not a UI 
- not a business layer

It provides a **secure, extensible foundation** for authentication and authorization while keeping the rest of the application clean and independent of auth details.
