package api

import (
	"github.com/kararnab/iam"
	"github.com/kararnab/iam/memstore"
	"github.com/kararnab/iam/password"
)

type Handlers struct {
	IAM       iam.Service
	Users     *memstore.Users
	Passwords *password.Provider
}

func NewHandlers(
	iamSvc iam.Service,
	users *memstore.Users,
	passwords *password.Provider,
) *Handlers {
	return &Handlers{
		IAM:       iamSvc,
		Users:     users,
		Passwords: passwords,
	}
}
