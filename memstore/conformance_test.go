package memstore_test

import (
	"testing"

	"github.com/kararnab/iam/v2/invite"
	"github.com/kararnab/iam/v2/memstore"
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
	t.Run("users", func(t *testing.T) {
		storetest.Users(t, func(*testing.T) storetest.UserStore { return memstore.NewUsers() })
	})
}
