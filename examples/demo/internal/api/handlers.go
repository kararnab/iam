package api

import (
	"github.com/kararnab/iam"
)

type Handlers struct {
	IAM iam.Service
}

func NewHandlers(iamSvc iam.Service) *Handlers {
	return &Handlers{IAM: iamSvc}
}
