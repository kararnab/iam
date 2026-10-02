package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/kararnab/iam"
	"github.com/kararnab/iam/policy"
)

type ctxKey string

const subjectKey ctxKey = "subject"

func AuthMiddleware(iamSvc iam.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			auth := r.Header.Get("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "missing token", http.StatusUnauthorized)
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")

			subject, _, err := iamSvc.VerifyAccessToken(r.Context(), token)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), subjectKey, subject)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func PolicyMiddleware(
	iamSvc iam.Service,
	action policy.Action,
	resource policy.Resource,
) func(http.Handler) http.Handler {

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			subject, ok := SubjectFromContext(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			decision, err := iamSvc.Authorize(
				r.Context(),
				subject,
				action,
				resource,
			)
			if err != nil || decision.Effect == policy.EffectDeny {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func SubjectFromContext(ctx context.Context) (*iam.Subject, bool) {
	s, ok := ctx.Value(subjectKey).(*iam.Subject)
	return s, ok
}
