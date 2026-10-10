package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2/session"
)

// Sessions implements session.Store.
type Sessions struct{ db DB }

var (
	_ session.Store  = (*Sessions)(nil)
	_ session.Purger = (*Sessions)(nil)
)

// NewSessions returns a session store.
func NewSessions(db DB) *Sessions { return &Sessions{db: db} }

const sessionCols = `id, subject_id, mode, token_hash, created_at, last_used_at, expires_at, attrs`

func scanSession(row pgx.Row, extra ...any) (*session.Session, error) {
	var s session.Session
	var mode string
	dest := append([]any{&s.ID, &s.SubjectID, &mode, &s.TokenHash, &s.CreatedAt, &s.LastUsedAt, &s.ExpiresAt, &s.Attrs}, extra...)
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, session.ErrNotFound
		}
		return nil, err
	}
	s.Mode = session.Mode(mode)
	return &s, nil
}

// Create implements session.Store.
func (m *Sessions) Create(ctx context.Context, s *session.Session) error {
	attrs := s.Attrs
	if attrs == nil {
		attrs = map[string]string{}
	}
	_, err := m.db.Exec(ctx, `INSERT INTO iam_sessions (`+sessionCols+`) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		s.ID, s.SubjectID, string(s.Mode), s.TokenHash, s.CreatedAt, s.LastUsedAt, s.ExpiresAt, attrs)
	return err
}

// Get implements session.Store.
func (m *Sessions) Get(ctx context.Context, id string) (*session.Session, error) {
	return scanSession(m.db.QueryRow(ctx, `SELECT `+sessionCols+` FROM iam_sessions WHERE id = $1`, id))
}

// GetByTokenHash implements session.Store.
func (m *Sessions) GetByTokenHash(ctx context.Context, hash []byte) (*session.Session, session.TokenState, error) {
	var rotatedAt *time.Time
	s, err := scanSession(m.db.QueryRow(ctx, `
		SELECT `+sessionCols+`, NULL::timestamptz FROM iam_sessions WHERE token_hash = $1
		UNION ALL
		SELECT s.id, s.subject_id, s.mode, s.token_hash, s.created_at, s.last_used_at, s.expires_at, s.attrs, r.rotated_at
		  FROM iam_rotated_tokens r JOIN iam_sessions s ON s.id = r.session_id
		 WHERE r.token_hash = $1
		LIMIT 1`, hash), &rotatedAt)
	if err != nil {
		return nil, session.TokenState{}, err
	}
	var state session.TokenState
	if rotatedAt != nil {
		state.RotatedAt = *rotatedAt
	}
	return s, state, nil
}

// Rotate implements session.Store. The compare-and-swap is a single
// UPDATE ... WHERE token_hash = old, so concurrent rotations of the same
// token cannot both succeed.
func (m *Sessions) Rotate(ctx context.Context, id string, oldHash, newHash []byte, at time.Time) error {
	tag, err := m.db.Exec(ctx, `
		WITH upd AS (
			UPDATE iam_sessions SET token_hash = $3, last_used_at = $4
			 WHERE id = $1 AND token_hash = $2
			RETURNING id
		)
		INSERT INTO iam_rotated_tokens (token_hash, session_id, rotated_at)
		SELECT $2, id, $4 FROM upd`, id, oldHash, newHash, at)
	if err != nil {
		if isUniqueViolation(err) {
			return session.ErrConflict
		}
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := m.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM iam_sessions WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return session.ErrNotFound
	}
	return session.ErrConflict
}

// Touch implements session.Store.
func (m *Sessions) Touch(ctx context.Context, id string, at time.Time) error {
	tag, err := m.db.Exec(ctx, `UPDATE iam_sessions SET last_used_at = $2 WHERE id = $1`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return session.ErrNotFound
	}
	return nil
}

// Delete implements session.Store. Rotated hashes go with the session
// (ON DELETE CASCADE).
func (m *Sessions) Delete(ctx context.Context, id string) error {
	_, err := m.db.Exec(ctx, `DELETE FROM iam_sessions WHERE id = $1`, id)
	return err
}

// ListBySubject implements session.Store.
func (m *Sessions) ListBySubject(ctx context.Context, subjectID string) ([]*session.Session, error) {
	rows, err := m.db.Query(ctx, `SELECT `+sessionCols+` FROM iam_sessions WHERE subject_id = $1 ORDER BY created_at, id`, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*session.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteBySubject implements session.Store.
func (m *Sessions) DeleteBySubject(ctx context.Context, subjectID, exceptID string) (int, error) {
	tag, err := m.db.Exec(ctx, `DELETE FROM iam_sessions WHERE subject_id = $1 AND id <> $2`, subjectID, exceptID)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// PurgeExpired implements session.Purger: it deletes sessions past their
// absolute expiry (rotated hashes go with them, ON DELETE CASCADE). Run it
// periodically (for example hourly); expired sessions are already rejected.
func (m *Sessions) PurgeExpired(ctx context.Context, now time.Time) (int, error) {
	tag, err := m.db.Exec(ctx, `DELETE FROM iam_sessions WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
