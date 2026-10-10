package pgstore

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2"
	"github.com/kararnab/iam/v2/password"
	"github.com/kararnab/iam/v2/provider"
)

// Users implements iam.UserStore and password.CredentialStore.
type Users struct{ db DB }

var (
	_ iam.UserStore            = (*Users)(nil)
	_ iam.SubjectDeleter       = (*Users)(nil)
	_ password.CredentialStore = (*Users)(nil)
)

// NewUsers returns a user store.
func NewUsers(db DB) *Users { return &Users{db: db} }

// PutSubject creates or replaces a subject (roles, attributes, disabled).
func (u *Users) PutSubject(ctx context.Context, s iam.Subject) error {
	roles := s.Roles
	if roles == nil {
		roles = []string{}
	}
	attrs := s.Attrs
	if attrs == nil {
		attrs = map[string]string{}
	}
	_, err := u.db.Exec(ctx, `
		INSERT INTO iam_subjects (id, roles, attrs, disabled) VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET roles = EXCLUDED.roles, attrs = EXCLUDED.attrs, disabled = EXCLUDED.disabled`,
		s.ID, roles, attrs, s.Disabled)
	return err
}

// LoadSubject implements iam.SubjectLoader.
func (u *Users) LoadSubject(ctx context.Context, subjectID string) (*iam.Subject, error) {
	s := iam.Subject{ID: subjectID}
	err := u.db.QueryRow(ctx, `SELECT roles, attrs, disabled FROM iam_subjects WHERE id = $1`, subjectID).
		Scan(&s.Roles, &s.Attrs, &s.Disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, iam.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ResolveIdentity implements iam.IdentityStore.
func (u *Users) ResolveIdentity(ctx context.Context, prov, providerID string) (string, error) {
	var id string
	err := u.db.QueryRow(ctx, `SELECT subject_id FROM iam_identities WHERE provider = $1 AND provider_id = $2`, prov, providerID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrNotFound
	}
	return id, err
}

// LinkIdentity implements iam.IdentityStore.
func (u *Users) LinkIdentity(ctx context.Context, subjectID string, id provider.Identity) error {
	_, err := u.db.Exec(ctx, `
		INSERT INTO iam_identities (provider, provider_id, subject_id, email) VALUES ($1, $2, $3, $4)`,
		id.Provider, id.ProviderID, subjectID, id.Email)
	switch {
	case isUniqueViolation(err):
		return iam.ErrConflict
	case isForeignKeyViolation(err):
		return iam.ErrNotFound
	}
	return err
}

// UnlinkIdentity implements iam.IdentityStore.
func (u *Users) UnlinkIdentity(ctx context.Context, subjectID, prov, providerID string) error {
	_, err := u.db.Exec(ctx, `DELETE FROM iam_identities WHERE provider = $1 AND provider_id = $2 AND subject_id = $3`, prov, providerID, subjectID)
	return err
}

// CreateSubject implements iam.IdentityStore.
func (u *Users) CreateSubject(ctx context.Context, _ provider.Identity, grant iam.SignupGrant) (string, error) {
	id := rand.Text()
	roles := grant.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := u.db.Exec(ctx, `INSERT INTO iam_subjects (id, roles) VALUES ($1, $2)`, id, roles)
	if err != nil {
		return "", err
	}
	return id, nil
}

// DeleteSubject implements iam.SubjectDeleter. Linked identities go with
// it (ON DELETE CASCADE).
func (u *Users) DeleteSubject(ctx context.Context, subjectID string) error {
	_, err := u.db.Exec(ctx, `DELETE FROM iam_subjects WHERE id = $1`, subjectID)
	return err
}

// GetCredential implements password.CredentialStore.
func (u *Users) GetCredential(ctx context.Context, login string) (string, error) {
	var h string
	err := u.db.QueryRow(ctx, `SELECT password_hash FROM iam_credentials WHERE login = $1`, login).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iam.ErrNotFound
	}
	return h, err
}

// CreateCredential implements password.CredentialStore.
func (u *Users) CreateCredential(ctx context.Context, login, encodedHash string) error {
	_, err := u.db.Exec(ctx, `INSERT INTO iam_credentials (login, password_hash) VALUES ($1, $2)`, login, encodedHash)
	if isUniqueViolation(err) {
		return iam.ErrConflict
	}
	return err
}

// UpdateCredential implements password.CredentialStore.
func (u *Users) UpdateCredential(ctx context.Context, login, encodedHash string) error {
	tag, err := u.db.Exec(ctx, `UPDATE iam_credentials SET password_hash = $2, updated_at = now() WHERE login = $1`, login, encodedHash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return iam.ErrNotFound
	}
	return nil
}

// DeleteCredential implements password.CredentialStore.
func (u *Users) DeleteCredential(ctx context.Context, login string) error {
	_, err := u.db.Exec(ctx, `DELETE FROM iam_credentials WHERE login = $1`, login)
	return err
}
