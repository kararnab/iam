# Demo: books API

A small books API built on [`github.com/kararnab/iam/v2`](../../README.md). It
imports the library like any consumer and shows:

- cookie sessions for browsers (with CSRF tokens) and bearer tokens for API
  clients, side by side;
- invite-only sign-up (or open sign-up with `IAM_SIGNUP=open`);
- RBAC: `admin` can do anything, `editor` can read and write books,
  `reader` can only read them;
- refresh-token rotation and reuse detection, session listing and "log out
  everywhere else";
- login throttling, audit logs (slog) and Prometheus metrics;
- TOTP multi-factor authentication (set `IAM_MFA_KEY`; on in `-dev`);
- password reset and email verification (the links are logged in `-dev`;
  the demo sends no email);
- in-memory stores, or PostgreSQL with `IAM_DATABASE_URL`.

## Run

```sh
cd examples/demo
go run . -dev
```

`-dev` serves cookies over plain HTTP, generates a random signing key if
`IAM_SIGNING_KEY` is unset, and seeds the **public** demo admin
`admin@gmail.com` / `p@$$w0rd1`. Never use `-dev` outside your own machine.

Without `-dev` the server refuses to start without `IAM_SIGNING_KEY`, and
creates an admin only from `IAM_ADMIN_EMAIL` / `IAM_ADMIN_PASSWORD`. All
settings are listed in [`.env.example`](../../.env.example).

With Docker, from the repository root:

```sh
docker build -f examples/demo/Dockerfile -t kararnab/iam-demo .
docker run -p 8080:8080 --env-file .env kararnab/iam-demo
```

The API listens on `:8080` (`PORT`). Metrics are served on
`127.0.0.1:9090/metrics` (`ADMIN_ADDR`), never on the public port.

## API

The full contract is [`openapi.yaml`](openapi.yaml). Open it in Swagger UI:

```sh
docker run -p 8081:8080 -e SWAGGER_JSON=/spec/openapi.yaml \
  -v "$PWD/openapi.yaml:/spec/openapi.yaml" swaggerapi/swagger-ui
```

Hoppscotch and Postman can import the same file.

### Bearer tokens

```sh
B=localhost:8080
LOGIN='{"provider":"password","params":{"username":"admin@gmail.com","password":"p@$$w0rd1"}}'

curl -s $B/api/login -d "$LOGIN"                     # access_token, refresh_token, subject, session
curl -s $B/api/books -H "Authorization: Bearer $AT"
curl -s $B/api/refresh -d "{\"refresh_token\":\"$RT\"}"   # new pair; the old refresh token is now dead
curl -s $B/api/logout  -d "{\"refresh_token\":\"$RT2\"}"
```

### Cookie session

```sh
curl -s -c jar $B/api/session/login -d "$LOGIN"      # sets the cookie, returns csrf_token
curl -s -b jar $B/api/me
curl -s -b jar $B/api/invites -H "X-CSRF-Token: $CSRF" -d '{"roles":["editor"]}'   # invite token
curl -s -b jar -X POST $B/api/session/logout -H "X-CSRF-Token: $CSRF"
```

Then sign someone up with the invite:

```sh
curl -s -c jar2 $B/api/session/register \
  -d "{\"username\":\"ed@example.com\",\"password\":\"editor password!\",\"invite\":\"$INVITE\"}"
```

### Endpoints

| Endpoint | Auth | Policy |
|---|---|---|
| `POST /api/login`, `/api/register`, `/api/refresh`, `/api/logout` | – | bearer tokens in JSON |
| `POST /api/session/login`, `/api/session/register` | – | sets the session cookie |
| `GET /api/session`, `POST /api/session/logout` | cookie | |
| `GET /api/me`, `GET /api/sessions`, `DELETE /api/sessions/{id}`, `POST /api/sessions/revoke-others`, `POST /api/identities` | either | |
| `POST /api/password/forgot`, `/api/password/reset`, `/api/email/verify` | – | links are logged in `-dev`, never emailed |
| `POST /api/email/verification` | either | |
| `POST /api/login/mfa`, `/api/session/login/mfa` | – | completes a login that answered `401 mfa_required` |
| `POST /api/mfa/totp`, `/api/mfa/totp/confirm`, `DELETE /api/mfa/totp` | either | enroll, confirm, disable (needs a code) |
| `GET /api/books`, `GET /api/books/{id}` | either | `read` on `book` |
| `POST /api/books`, `PUT`/`DELETE /api/books/{id}` | either | `write` on `book` |
| `POST /api/invites` | either | `create` on `invite` (admin) |
| `POST /admin/keys/rotate` | either | `rotate` on `signing_key` (admin) |

Cookie-authenticated `POST`, `PUT` and `DELETE` requests need the
`X-CSRF-Token` header. Cross-origin browser requests are rejected.

## Tests

```sh
go test -race ./...
IAM_TEST_POSTGRES_DSN='postgres://…' go test -race ./...   # end-to-end on PostgreSQL
```

`e2e_test.go` drives the cookie flow (invite, sign-up, CSRF, revoke others,
logout), the bearer flow (rotation, reuse detection, key rotation, logout),
throttling, password reset and email verification, TOTP enrollment and MFA
login, permissions and the request size limit.
