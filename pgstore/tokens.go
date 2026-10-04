package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2/onetime"
)

// Tokens implements onetime.Store.
type Tokens struct{ db DB }

var _ onetime.Store = (*Tokens)(nil)

// NewTokens returns a one-time token store.
func NewTokens(db DB) *Tokens { return &Tokens{db: db} }

const tokenCols = `id, token_hash, purpose, subject_id, login, email, created_at, expires_at, used_at` //nolint:gosec // G101: column names, not a credential

func scanToken(row pgx.Row) (*onetime.Token, error) {
	var t onetime.Token
	var purpose string
	var usedAt *time.Time
	if err := row.Scan(&t.ID, &t.TokenHash, &purpose, &t.SubjectID, &t.Login, &t.Email, &t.CreatedAt, &t.ExpiresAt, &usedAt); err != nil {
		return nil, err
	}
	t.Purpose = onetime.Purpose(purpose)
	if usedAt != nil {
		t.UsedAt = *usedAt
	}
	return &t, nil
}

// Create implements onetime.Store.
func (s *Tokens) Create(ctx context.Context, t *onetime.Token) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO iam_one_time_tokens (id, token_hash, purpose, subject_id, login, email, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID, t.TokenHash, string(t.Purpose), t.SubjectID, t.Login, t.Email, t.CreatedAt, t.ExpiresAt)
	return err
}

// GetByTokenHash implements onetime.Store.
func (s *Tokens) GetByTokenHash(ctx context.Context, hash []byte) (*onetime.Token, error) {
	t, err := scanToken(s.db.QueryRow(ctx, `SELECT `+tokenCols+` FROM iam_one_time_tokens WHERE token_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, onetime.ErrNotFound
	}
	return t, err
}

// Consume implements onetime.Store with a single conditional UPDATE.
func (s *Tokens) Consume(ctx context.Context, hash []byte, purpose onetime.Purpose, at time.Time) (*onetime.Token, error) {
	t, err := scanToken(s.db.QueryRow(ctx, `
		UPDATE iam_one_time_tokens SET used_at = $3
		 WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3
		RETURNING `+tokenCols, hash, string(purpose), at))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, onetime.ErrInvalid
	}
	return t, err
}

// DeleteBySubject implements onetime.Store.
func (s *Tokens) DeleteBySubject(ctx context.Context, subjectID string, purpose onetime.Purpose) error {
	_, err := s.db.Exec(ctx, `DELETE FROM iam_one_time_tokens WHERE subject_id = $1 AND purpose = $2`, subjectID, string(purpose))
	return err
}

// PurgeExpired deletes tokens past their expiry. Run it periodically
// (for example hourly); expired tokens are already rejected.
func (s *Tokens) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM iam_one_time_tokens WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
