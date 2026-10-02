package secrets

import "context"

type DummyStore struct{}

func NewDummyStore() *DummyStore {
	return &DummyStore{}
}

// Get ⚠️ NEVER hardcode secrets in prod
func (d *DummyStore) Get(_ context.Context, name string) (string, error) {
	switch name {
	case "SECRET_USERNAME":
		return "admin@gmail.com", nil
	case "SECRET_USER_PASSWORD":
		return "p@$$w0rd1", nil
	case "SECRET_USER_ID":
		return "user-1", nil
	case "SECRET_JWT_SIGNING_KEY":
		return "dev-secret", nil
	case "SECRET_PASETO_SIGNING_KEY":
		return "", nil
	case "GOOGLE_OAUTH_CLIENTID":
		return "", nil
	default:
		return "", ErrNotFound
	}
}
