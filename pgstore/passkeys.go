package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2/passkey"
)

// Passkeys implements passkey.Store.
type Passkeys struct{ db DB }

var _ passkey.Store = (*Passkeys)(nil)

// NewPasskeys returns a credential store.
func NewPasskeys(db DB) *Passkeys { return &Passkeys{db: db} }

//nolint:gosec // G101: column names, not a credential
const passkeyCols = `id, subject_id, name, public_key, attestation_type, attestation_format, aaguid, transports,
	sign_count, user_present, user_verified, backup_eligible, backup_state, created_at, last_used_at`

func scanPasskey(row pgx.Row) (*passkey.Credential, error) {
	var c passkey.Credential
	var signCount int64
	var lastUsed *time.Time
	if err := row.Scan(&c.ID, &c.SubjectID, &c.Name, &c.PublicKey, &c.AttestationType, &c.AttestationFormat, &c.AAGUID,
		&c.Transports, &signCount, &c.UserPresent, &c.UserVerified, &c.BackupEligible, &c.BackupState, &c.CreatedAt, &lastUsed); err != nil {
		return nil, err
	}
	c.SignCount = uint32(signCount) //nolint:gosec // G115: stored from a uint32
	if lastUsed != nil {
		c.LastUsedAt = *lastUsed
	}
	return &c, nil
}

// Create implements passkey.Store.
func (s *Passkeys) Create(ctx context.Context, c *passkey.Credential) error {
	transports := c.Transports
	if transports == nil {
		transports = []string{}
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO iam_passkeys (id, subject_id, name, public_key, attestation_type, attestation_format, aaguid, transports,
			sign_count, user_present, user_verified, backup_eligible, backup_state, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		c.ID, c.SubjectID, c.Name, c.PublicKey, c.AttestationType, c.AttestationFormat, c.AAGUID, transports,
		int64(c.SignCount), c.UserPresent, c.UserVerified, c.BackupEligible, c.BackupState, c.CreatedAt)
	if isUniqueViolation(err) {
		return passkey.ErrConflict
	}
	return err
}

// Get implements passkey.Store.
func (s *Passkeys) Get(ctx context.Context, id []byte) (*passkey.Credential, error) {
	c, err := scanPasskey(s.db.QueryRow(ctx, `SELECT `+passkeyCols+` FROM iam_passkeys WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, passkey.ErrNotFound
	}
	return c, err
}

// ListBySubject implements passkey.Store.
func (s *Passkeys) ListBySubject(ctx context.Context, subjectID string) ([]*passkey.Credential, error) {
	rows, err := s.db.Query(ctx, `SELECT `+passkeyCols+` FROM iam_passkeys WHERE subject_id = $1 ORDER BY created_at, id`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*passkey.Credential
	for rows.Next() {
		c, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Touch implements passkey.Store.
func (s *Passkeys) Touch(ctx context.Context, id []byte, signCount uint32, backupState bool, at time.Time) error {
	tag, err := s.db.Exec(ctx, `UPDATE iam_passkeys SET sign_count = $2, backup_state = $3, last_used_at = $4 WHERE id = $1`,
		id, int64(signCount), backupState, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return passkey.ErrNotFound
	}
	return nil
}

// Delete implements passkey.Store.
func (s *Passkeys) Delete(ctx context.Context, subjectID string, id []byte) error {
	_, err := s.db.Exec(ctx, `DELETE FROM iam_passkeys WHERE id = $1 AND subject_id = $2`, id, subjectID)
	return err
}
