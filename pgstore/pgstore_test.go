package pgstore

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/mfa"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/passkey"
	"github.com/kararnab/iam/v2/ratelimit"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/storetest"
)

// newPool connects to IAM_TEST_POSTGRES_DSN, resets the iam tables and
// runs Migrate. Without the variable the tests are skipped.
func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool := emptyPool(t)
	if err := Migrate(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

// emptyPool connects to IAM_TEST_POSTGRES_DSN and drops the iam tables.
func emptyPool(t *testing.T) *pgxpool.Pool {
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
		iam_identities, iam_credentials, iam_subjects, iam_one_time_tokens, iam_mfa_totp, iam_passkeys, iam_rate_limits, iam_schema_migrations,
		iam_schema_migrations_sessions, iam_schema_migrations_users CASCADE`); err != nil {
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
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam_schema_migrations`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("migrations recorded = %d, %v", n, err)
	}
}

func TestConformance(t *testing.T) {
	t.Run("sessions", func(t *testing.T) {
		storetest.Sessions(t, func(t *testing.T) session.Store { return NewSessions(newPool(t)) })
	})
	t.Run("purger", func(t *testing.T) {
		storetest.Purger(t, func(t *testing.T) storetest.PurgingSessionStore { return NewSessions(newPool(t)) })
	})
	t.Run("invites", func(t *testing.T) {
		storetest.Invites(t, func(t *testing.T) invite.Store { return NewInvites(newPool(t)) })
	})
	t.Run("invite manager", func(t *testing.T) {
		storetest.InviteManager(t, func(t *testing.T) storetest.ManagedInviteStore { return NewInvites(newPool(t)) })
	})
	t.Run("tokens", func(t *testing.T) {
		storetest.Tokens(t, func(t *testing.T) onetime.Store { return NewTokens(newPool(t)) })
	})
	t.Run("limiter", func(t *testing.T) {
		storetest.Limiter(t, func(t *testing.T, cfg ratelimit.Config) ratelimit.Limiter {
			l, err := NewLimiter(newPool(t), cfg)
			if err != nil {
				t.Fatal(err)
			}
			return l
		})
	})
	t.Run("mfa", func(t *testing.T) {
		storetest.MFA(t, func(t *testing.T) mfa.Store { return NewMFA(newPool(t)) })
	})
	t.Run("passkeys", func(t *testing.T) {
		storetest.Passkeys(t, func(t *testing.T) passkey.Store { return NewPasskeys(newPool(t)) })
	})
	t.Run("users", func(t *testing.T) {
		storetest.Users(t, func(t *testing.T) storetest.UserStore { return NewUsers(newPool(t)) })
	})
}

// statements returns the normalized SQL statements of every migration in
// dir: comments removed, whitespace collapsed, sorted.
func statements(t *testing.T, fsys fs.FS, dir string) []string {
	t.Helper()
	files, err := fs.Glob(fsys, dir+"/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations in %s: %v", dir, err)
	}
	comment := regexp.MustCompile(`--[^\n]*`)
	var out []string
	for _, f := range files {
		body, err := fs.ReadFile(fsys, f)
		if err != nil {
			t.Fatal(err)
		}
		for stmt := range strings.SplitSeq(comment.ReplaceAllString(string(body), ""), ";") {
			if stmt = strings.Join(strings.Fields(stmt), " "); stmt != "" {
				out = append(out, stmt)
			}
		}
	}
	slices.Sort(out)
	return out
}

// TestMigrationSetsPartitionTheFullSet: SessionMigrations and UserMigrations
// together hold exactly the statements of Migrations. A schema change must
// go into the full set and into the partial set that owns its tables.
func TestMigrationSetsPartitionTheFullSet(t *testing.T) {
	full := statements(t, Migrations, "migrations")
	sessions := statements(t, SessionMigrations, "migrations/sessions")
	users := statements(t, UserMigrations, "migrations/users")

	parts := slices.Concat(sessions, users)
	slices.Sort(parts)
	if !slices.Equal(full, parts) {
		t.Fatalf("partial sets differ from the full set\nfull:  %q\nparts: %q", full, parts)
	}
	for _, stmt := range sessions {
		for _, table := range []string{"iam_subjects", "iam_identities", "iam_credentials"} {
			if strings.Contains(stmt, table) {
				t.Errorf("session set touches user table %s: %s", table, stmt)
			}
		}
	}
}

func TestMigrateSessionsAndUsers(t *testing.T) {
	pool := emptyPool(t)
	ctx := context.Background()

	if err := MigrateSessions(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := MigrateSessions(ctx, pool); err != nil {
		t.Fatalf("second MigrateSessions: %v", err)
	}
	var users bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('iam_subjects') IS NOT NULL`).Scan(&users); err != nil || users {
		t.Fatalf("MigrateSessions created the user tables (%v, %v)", users, err)
	}
	if err := Migrate(ctx, pool); !errors.Is(err, ErrMigrationSetConflict) {
		t.Fatalf("Migrate after MigrateSessions = %v, want ErrMigrationSetConflict", err)
	}

	if err := MigrateUsers(ctx, pool); err != nil {
		t.Fatal(err)
	}
	t.Run("sessions", func(t *testing.T) {
		storetest.Sessions(t, func(t *testing.T) session.Store {
			_, _ = pool.Exec(ctx, `TRUNCATE iam_sessions, iam_rotated_tokens`)
			return NewSessions(pool)
		})
	})
	t.Run("invites", func(t *testing.T) {
		storetest.Invites(t, func(t *testing.T) invite.Store {
			_, _ = pool.Exec(ctx, `TRUNCATE iam_invites`)
			return NewInvites(pool)
		})
	})
	t.Run("tokens", func(t *testing.T) {
		storetest.Tokens(t, func(t *testing.T) onetime.Store {
			_, _ = pool.Exec(ctx, `TRUNCATE iam_one_time_tokens`)
			return NewTokens(pool)
		})
	})
	t.Run("mfa", func(t *testing.T) {
		storetest.MFA(t, func(t *testing.T) mfa.Store {
			_, _ = pool.Exec(ctx, `TRUNCATE iam_mfa_totp`)
			return NewMFA(pool)
		})
	})
	t.Run("passkeys", func(t *testing.T) {
		storetest.Passkeys(t, func(t *testing.T) passkey.Store {
			_, _ = pool.Exec(ctx, `TRUNCATE iam_passkeys`)
			return NewPasskeys(pool)
		})
	})
	t.Run("users", func(t *testing.T) {
		storetest.Users(t, func(t *testing.T) storetest.UserStore {
			_, _ = pool.Exec(ctx, `TRUNCATE iam_subjects, iam_identities, iam_credentials`)
			return NewUsers(pool)
		})
	})
}

func TestPartialSetAfterMigrateConflicts(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	if err := MigrateSessions(ctx, pool); !errors.Is(err, ErrMigrationSetConflict) {
		t.Fatalf("MigrateSessions after Migrate = %v, want ErrMigrationSetConflict", err)
	}
	if err := MigrateUsers(ctx, pool); !errors.Is(err, ErrMigrationSetConflict) {
		t.Fatalf("MigrateUsers after Migrate = %v, want ErrMigrationSetConflict", err)
	}
}

func TestLimiterPurgeExpired(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	now := time.Now().Truncate(time.Second)
	l, err := NewLimiter(pool, ratelimit.Config{Threshold: 2, Window: time.Minute, BaseDelay: time.Hour, MaxDelay: time.Hour,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = l.Fail(ctx, "short")
	for range 2 {
		_, _ = l.Fail(ctx, "blocked") // blocked for an hour: kept past the window
	}

	if n, err := l.PurgeExpired(ctx, now.Add(59*time.Second)); err != nil || n != 0 {
		t.Fatalf("purge inside the window = %d, %v", n, err)
	}
	// Expiry is inclusive: at the end of the window the row is dead.
	if n, err := l.PurgeExpired(ctx, now.Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("purge at the end of the window = %d, %v", n, err)
	}
	if r, err := l.Check(ctx, "blocked"); err != nil || r.Allowed || r.Failures != 2 {
		t.Fatalf("blocked key after purge = %+v, %v", r, err)
	}
	if n, err := l.PurgeExpired(ctx, now.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("purge after the block = %d, %v", n, err)
	}
}
