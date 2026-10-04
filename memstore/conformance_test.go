package memstore_test

import (
	"testing"

	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/memstore"
	"github.com/kararnab/iam/v2/onetime"
	"github.com/kararnab/iam/v2/session"
	"github.com/kararnab/iam/v2/storetest"
)

func TestConformance(t *testing.T) {
	t.Run("sessions", func(t *testing.T) {
		storetest.Sessions(t, func(*testing.T) session.Store { return memstore.NewSessions() })
	})
	t.Run("invites", func(t *testing.T) {
		storetest.Invites(t, func(*testing.T) invite.Store { return memstore.NewInvites() })
	})
	t.Run("tokens", func(t *testing.T) {
		storetest.Tokens(t, func(*testing.T) onetime.Store { return memstore.NewTokens() })
	})
	t.Run("users", func(t *testing.T) {
		storetest.Users(t, func(*testing.T) storetest.UserStore { return memstore.NewUsers() })
	})
	t.Run("users with one role", func(t *testing.T) {
		storetest.UsersWith(t, func(*testing.T) storetest.UserStore { return memstore.NewUsers() },
			storetest.UsersOptions{Roles: []string{"admin"}, DefaultRoles: []string{"learner"}})
	})
}
