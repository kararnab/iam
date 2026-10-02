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

// Migrations holds the SQL migrations, named NNNN_description.sql.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// migrationLock is the advisory lock key that serializes concurrent Migrate
// calls (for example several instances starting at once).
const migrationLock = 0x69616d5f6d6967 // "iam_mig"

// Migrate applies pending migrations in order, each in its own transaction.
func Migrate(ctx context.Context, db DB) error {
	files, err := fs.Glob(Migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(migrationLock)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS iam_schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}

	for _, f := range files {
		name := strings.TrimPrefix(f, "migrations/")
		num, _, ok := strings.Cut(name, "_")
		version, err := strconv.Atoi(num)
		if !ok || err != nil {
			return fmt.Errorf("pgstore: bad migration file name %q", name)
		}
		var applied bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM iam_schema_migrations WHERE version = $1)`, version).Scan(&applied); err != nil {
			return err
		}
		if applied {
			continue
		}
		body, err := Migrations.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			return fmt.Errorf("pgstore: migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO iam_schema_migrations (version) VALUES ($1)`, version); err != nil {
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
