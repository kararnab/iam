package pgstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2/mfa"
)

// MFA implements mfa.Store.
type MFA struct{ db DB }

var _ mfa.Store = (*MFA)(nil)

// NewMFA returns an MFA store.
func NewMFA(db DB) *MFA { return &MFA{db: db} }

// GetTOTP implements mfa.Store.
func (s *MFA) GetTOTP(ctx context.Context, subjectID string) (*mfa.TOTP, error) {
	var t mfa.TOTP
	err := s.db.QueryRow(ctx, `
		SELECT subject_id, secret, confirmed, last_step, recovery_codes, created_at
		  FROM iam_mfa_totp WHERE subject_id = $1`, subjectID).
		Scan(&t.SubjectID, &t.Secret, &t.Confirmed, &t.LastStep, &t.RecoveryCodes, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, mfa.ErrNotFound
	}
	return &t, err
}

// PutTOTP implements mfa.Store.
func (s *MFA) PutTOTP(ctx context.Context, t *mfa.TOTP) error {
	codes := t.RecoveryCodes
	if codes == nil {
		codes = [][]byte{}
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO iam_mfa_totp (subject_id, secret, confirmed, last_step, recovery_codes, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (subject_id) DO UPDATE SET secret = EXCLUDED.secret, confirmed = EXCLUDED.confirmed,
			last_step = EXCLUDED.last_step, recovery_codes = EXCLUDED.recovery_codes, created_at = EXCLUDED.created_at`,
		t.SubjectID, t.Secret, t.Confirmed, t.LastStep, codes, t.CreatedAt)
	return err
}

// DeleteTOTP implements mfa.Store.
func (s *MFA) DeleteTOTP(ctx context.Context, subjectID string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM iam_mfa_totp WHERE subject_id = $1`, subjectID)
	return err
}

// AdvanceTOTP implements mfa.Store with a single conditional UPDATE.
func (s *MFA) AdvanceTOTP(ctx context.Context, subjectID string, step int64) (bool, error) {
	tag, err := s.db.Exec(ctx, `UPDATE iam_mfa_totp SET last_step = $2 WHERE subject_id = $1 AND last_step < $2`, subjectID, step)
	return err == nil && tag.RowsAffected() == 1, err
}

// UseRecoveryCode implements mfa.Store with a single conditional UPDATE.
func (s *MFA) UseRecoveryCode(ctx context.Context, subjectID string, hash []byte) (bool, error) {
	tag, err := s.db.Exec(ctx, `
		UPDATE iam_mfa_totp SET recovery_codes = array_remove(recovery_codes, $2::bytea)
		 WHERE subject_id = $1 AND $2::bytea = ANY(recovery_codes)`, subjectID, hash)
	return err == nil && tag.RowsAffected() == 1, err
}
