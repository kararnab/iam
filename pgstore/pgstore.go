// Package pgstore implements the iam stores on PostgreSQL with pgx.
//
//	pool, _ := pgxpool.New(ctx, dsn)
//	if err := pgstore.Migrate(ctx, pool); err != nil { ... }
//	cfg := iam.Config{
//	    Users:    pgstore.NewUsers(pool),
//	    Sessions: pgstore.NewSessions(pool),
//	    Signup:   iam.SignupConfig{Invites: pgstore.NewInvites(pool)},
//	    ...
//	}
//
// The schema lives in migrations/*.sql (embedded). Run Migrate at start-up,
// or copy the files into your own migration tool.
//
// An application that implements iam.UserStore over its own tables needs
// only the session, invite and one-time token tables: run MigrateSessions instead, or copy
// SessionMigrations. UserMigrations holds the rest. The two sets together
// create exactly the tables of the full set.
package pgstore

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the subset of *pgxpool.Pool (or *pgx.Conn) the stores use.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
}

// Migrations holds the SQL migrations, named NNNN_description.sql: every
// pgstore table. Migrate applies it.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// SessionMigrations holds the migrations for every table that does not
// hold pgstore's own users (iam_sessions, iam_rotated_tokens, iam_invites,
// iam_one_time_tokens, iam_mfa_totp, iam_passkeys), under
// migrations/sessions/. MigrateSessions applies it.
//
//go:embed migrations/sessions/*.sql
var SessionMigrations embed.FS

// UserMigrations holds the migrations for the user tables only
// (iam_subjects, iam_identities, iam_credentials), under migrations/users/.
// MigrateUsers applies it.
//
//go:embed migrations/users/*.sql
var UserMigrations embed.FS

// ErrMigrationSetConflict is returned when a database was migrated with the
// full set and is then given a partial set, or the other way round. Each set
// creates its own tables, so mixing them would create a table twice.
var ErrMigrationSetConflict = errors.New("pgstore: database was migrated with a different migration set")

// A migrationSet is one embedded set of migrations and its tracker table.
type migrationSet struct {
	fsys      embed.FS
	dir       string
	tracker   string
	conflicts []string // trackers of the sets this one must not be mixed with
}

var (
	fullSet     = migrationSet{Migrations, "migrations", "iam_schema_migrations", []string{"iam_schema_migrations_sessions", "iam_schema_migrations_users"}}
	sessionsSet = migrationSet{SessionMigrations, "migrations/sessions", "iam_schema_migrations_sessions", []string{"iam_schema_migrations"}}
	usersSet    = migrationSet{UserMigrations, "migrations/users", "iam_schema_migrations_users", []string{"iam_schema_migrations"}}
)

// migrationLock is the advisory lock key that serializes concurrent Migrate
// calls (for example several instances starting at once).
const migrationLock = 0x69616d5f6d6967 // "iam_mig"

// Migrate applies pending migrations of the full set (Migrations) in order,
// recorded in iam_schema_migrations. It returns ErrMigrationSetConflict if
// MigrateSessions or MigrateUsers was used on the database.
func Migrate(ctx context.Context, db DB) error { return migrate(ctx, db, fullSet) }

// MigrateSessions applies pending migrations of SessionMigrations, recorded
// in iam_schema_migrations_sessions. Use it, instead of Migrate, when the
// application implements iam.UserStore over its own tables. It returns
// ErrMigrationSetConflict if Migrate was used on the database.
func MigrateSessions(ctx context.Context, db DB) error { return migrate(ctx, db, sessionsSet) }

// MigrateUsers applies pending migrations of UserMigrations, recorded in
// iam_schema_migrations_users. MigrateSessions and MigrateUsers together are
// equivalent to Migrate. It returns ErrMigrationSetConflict if Migrate was
// used on the database.
func MigrateUsers(ctx context.Context, db DB) error { return migrate(ctx, db, usersSet) }

// migrate applies the set's pending migrations in one transaction.
func migrate(ctx context.Context, db DB, set migrationSet) error {
	files, err := fs.Glob(set.fsys, set.dir+"/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	// Rollback after Commit is a no-op that returns pgx.ErrTxClosed.
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(migrationLock)); err != nil {
		return err
	}
	for _, other := range set.conflicts {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT to_regclass($1::text) IS NOT NULL`, other).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%w (%s exists)", ErrMigrationSetConflict, other)
		}
	}
	// The tracker name is one of the constants above, never input.
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS `+set.tracker+` (
		version    INTEGER PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	for _, f := range files {
		name := strings.TrimPrefix(f, set.dir+"/")
		num, _, ok := strings.Cut(name, "_")
		version, err := strconv.Atoi(num)
		if !ok || err != nil {
			return fmt.Errorf("pgstore: bad migration file name %q", name)
		}
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+set.tracker+` WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := set.fsys.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("pgstore: migration %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO `+set.tracker+` (version) VALUES ($1)`, version); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
