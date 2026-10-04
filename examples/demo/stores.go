package main

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kararnab/iam/pgstore/v2"
	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/mfa"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/session"
)

// stores bundles the demo's persistence: in memory by default, PostgreSQL
// when IAM_DATABASE_URL is set.
type stores struct {
	users interface {
		iam.UserStore
		password.CredentialStore
	}
	sessions   session.Store
	invites    invite.Store
	tokens     onetime.Store
	mfa        mfa.Store
	putSubject func(context.Context, iam.Subject) error
}

func newStores(ctx context.Context, databaseURL string) (*stores, error) {
	if databaseURL == "" {
		users := memstore.NewUsers()
		return &stores{
			users:    users,
			sessions: memstore.NewSessions(),
			invites:  memstore.NewInvites(),
			tokens:   memstore.NewTokens(),
			mfa:      memstore.NewMFA(),
			putSubject: func(_ context.Context, s iam.Subject) error {
				users.PutSubject(s)
				return nil
			},
		}, nil
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pgstore.Migrate(ctx, pool); err != nil {
		return nil, err
	}
	slog.Info("using PostgreSQL stores")
	users := pgstore.NewUsers(pool)
	return &stores{
		users:      users,
		sessions:   pgstore.NewSessions(pool),
		invites:    pgstore.NewInvites(pool),
		tokens:     pgstore.NewTokens(pool),
		mfa:        pgstore.NewMFA(pool),
		putSubject: users.PutSubject,
	}, nil
}
