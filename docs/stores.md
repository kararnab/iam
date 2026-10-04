# Stores

IAM persists four kinds of data. Each is an interface; in-memory versions
live in `memstore` (core), and durable ones in the `pgstore` and
`redisstore` modules.

| Interface | Holds | memstore | pgstore | redisstore |
|---|---|---|---|---|
| `iam.SubjectLoader` + `iam.IdentityStore` (= `iam.UserStore`) | subjects, roles, linked identities | `Users` | `Users` | – |
| `password.CredentialStore` | password hashes by login | `Users` | `Users` | – |
| `session.Store` | sessions and rotated token hashes | `Sessions` | `Sessions` | `Sessions` |
| `invite.Store` | invites | `Invites` | `Invites` | – |
| `ratelimit.Limiter` | failure counters | `ratelimit.Memory` | – | `Limiter` |

Users are **application-owned**. If you already have a users table,
implement `iam.UserStore` over it and use IAM's stores only for sessions and
invites.

## PostgreSQL (`github.com/kararnab/iam/pgstore/v2`)

```go
pool, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
if err := pgstore.Migrate(ctx, pool); err != nil { ... }

cfg := iam.Config{
    Users:    pgstore.NewUsers(pool),
    Sessions: pgstore.NewSessions(pool),
    Signup:   iam.SignupConfig{Invites: pgstore.NewInvites(pool)},
    // password.NewProvider(pgstore.NewUsers(pool), ...)
}
```

- The schema is in [`pgstore/migrations`](../pgstore/migrations), embedded
  in the module. `Migrate` applies pending files in order, records them in
  `iam_schema_migrations`, and takes an advisory lock so concurrent starts
  are safe. You can also copy the SQL into your own migration tool.
- Tables are prefixed `iam_`. `iam_sessions.subject_id` deliberately has no
  foreign key, so sessions also work with your own users table.
- Run `(*pgstore.Sessions).PurgeExpired` periodically. Expired sessions are
  rejected anyway; this only reclaims space.

### With your own user table

If you implement `iam.UserStore` over your own tables, you need only the
session and invite tables (`iam_sessions`, `iam_rotated_tokens`,
`iam_invites`). Create just those:

```go
if err := pgstore.MigrateSessions(ctx, pool); err != nil { ... }
```

or copy the files in `pgstore.SessionMigrations`
([`pgstore/migrations/sessions`](../pgstore/migrations/sessions)) into your
own migration tool. `pgstore.UserMigrations` holds the user tables, and the
two sets together create exactly what `Migrate` creates.

- Each set has its own tracker (`iam_schema_migrations_sessions`,
  `iam_schema_migrations_users`). Use either `Migrate`, or the partial sets;
  mixing them returns `pgstore.ErrMigrationSetConflict`.
- If you copy the SQL, pin the `pgstore` version and compare your copy with
  the embedded files in a test (`fs.ReadFile(pgstore.SessionMigrations, ...)`).
  Every schema change is a new numbered file in each set it touches, and the
  [changelog](../CHANGELOG.md) names the tables it changes.

### With `database/sql`

The stores use pgx's native interface (`pgstore.DB`: a `*pgxpool.Pool` or a
`*pgx.Conn`), not `database/sql`. If your application uses `database/sql`
with the pgx driver, either:

- **put both on one pool:** open a `*pgxpool.Pool` and derive your `*sql.DB`
  from it with `stdlib.OpenDBFromPool(pool)` (`github.com/jackc/pgx/v5/stdlib`).
  The stores and your code then share one set of connections; or
- **open a second, small pool** for the stores (sessions and invites need
  few connections; `MaxConns` of 2 to 5 is typical), and size both pools so
  that together they stay under the server's `max_connections`.

Both pools reach the same database, so your user table and the iam tables
can live side by side. Transactions do not span the two pools.

## Redis (`github.com/kararnab/iam/redisstore/v2`)

```go
rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
sessions := redisstore.NewSessions(rdb, "")             // keys under "{iam}:"
limiter, _ := redisstore.NewLimiter(rdb, "", ratelimit.Config{Threshold: 5})
```

All keys share one hash tag, so the Lua scripts stay atomic on Redis
Cluster. Session keys expire at the session's absolute expiry. Use the
Redis limiter when you run more than one instance; the in-memory limiter
counts per process.

## Writing a store

Read the interface documentation. The contracts that matter most:

- **`session.Store.Rotate` must be atomic:** compare the current token hash
  with `oldHash` and replace it in one step. If two concurrent rotations
  both succeeded, reuse detection would break. In SQL, use
  `UPDATE … WHERE id = $1 AND token_hash = $2`.
- `GetByTokenHash` must also find **rotated** hashes (with `RotatedAt` set)
  until the session is deleted. That is how reuse is detected.
- **`invite.Store.Consume` must be atomic:** at most one caller wins.
- Return the package's sentinel errors (`session.ErrNotFound`,
  `session.ErrConflict`, `iam.ErrNotFound`, `iam.ErrConflict`,
  `invite.ErrInvalid`, ...), because callers branch on them.
- Never store secrets. You only ever receive SHA-256 hashes, and should keep
  it that way.

Then run the conformance suite, which every built-in store passes:

```go
func TestMyStores(t *testing.T) {
    storetest.Sessions(t, func(t *testing.T) session.Store { return newMySessions(t) })
    storetest.Invites(t, func(t *testing.T) invite.Store { return newMyInvites(t) })
    storetest.Users(t, func(t *testing.T) storetest.UserStore { return newMyUsers(t) })
}
```
