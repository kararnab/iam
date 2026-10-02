package pgstore

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kararnab/iam/invite"
	"github.com/kararnab/iam/session"
	"github.com/kararnab/iam/storetest"
)

// newPool connects to IAM_TEST_POSTGRES_DSN and resets the iam tables.
// Without the variable the tests are skipped.
func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("IAM_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("IAM_TEST_POSTGRES_DSN not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS iam_rotated_tokens, iam_sessions, iam_invites,
		iam_identities, iam_credentials, iam_subjects, iam_schema_migrations CASCADE`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestMigrateIsIdempotentAndConcurrent(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	errs := make(chan error, 4)
	for range 4 {
		go func() { errs <- Migrate(ctx, pool) }()
	}
	for range 4 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_schema_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migrations recorded = %d, %v", n, err)
	}
}

func TestConformance(t *testing.T) {
	t.Run("sessions", func(t *testing.T) {
		storetest.Sessions(t, func(t *testing.T) session.Store { return NewSessions(newPool(t)) })
	})
	t.Run("invites", func(t *testing.T) {
		storetest.Invites(t, func(t *testing.T) invite.Store { return NewInvites(newPool(t)) })
	})
	t.Run("users", func(t *testing.T) {
		storetest.Users(t, func(t *testing.T) storetest.UserStore { return NewUsers(newPool(t)) })
	})
}
