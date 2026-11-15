package pgstore

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kararnab/iam/v2/invite"
)

// Invites implements invite.Store.
type Invites struct{ db DB }

var _ invite.Store = (*Invites)(nil)

// NewInvites returns an invite store.
func NewInvites(db DB) *Invites { return &Invites{db: db} }

const inviteCols = `id, token_hash, email, roles, created_by, created_at, expires_at, used_at, used_by`

func scanInvite(row pgx.Row) (*invite.Invite, error) {
	var inv invite.Invite
	var usedAt *time.Time
	if err := row.Scan(&inv.ID, &inv.TokenHash, &inv.Email, &inv.Roles, &inv.CreatedBy, &inv.CreatedAt, &inv.ExpiresAt, &usedAt, &inv.UsedBy); err != nil {
		return nil, err
	}
	if usedAt != nil {
		inv.UsedAt = *usedAt
	}
	return &inv, nil
}

// Create implements invite.Store.
func (s *Invites) Create(ctx context.Context, inv *invite.Invite) error {
	roles := inv.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := s.db.Exec(ctx, `
		INSERT INTO iam_invites (id, token_hash, email, roles, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		inv.ID, inv.TokenHash, inv.Email, roles, inv.CreatedBy, inv.CreatedAt, inv.ExpiresAt)
	return err
}

// GetByTokenHash implements invite.Store.
func (s *Invites) GetByTokenHash(ctx context.Context, hash []byte) (*invite.Invite, error) {
	inv, err := scanInvite(s.db.QueryRow(ctx, `SELECT `+inviteCols+` FROM iam_invites WHERE token_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, invite.ErrNotFound
	}
	return inv, err
}

// Consume implements invite.Store with a single conditional UPDATE.
func (s *Invites) Consume(ctx context.Context, hash []byte, usedBy string, at time.Time) (*invite.Invite, error) {
	inv, err := scanInvite(s.db.QueryRow(ctx, `
		UPDATE iam_invites SET used_at = $2, used_by = $3
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
		RETURNING `+inviteCols, hash, at, usedBy))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, invite.ErrInvalid
	}
	return inv, err
}

// Delete implements invite.Store.
func (s *Invites) Delete(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM iam_invites WHERE id = $1`, id)
	return err
}

var _ invite.Manager = (*Invites)(nil)

// ListUsable implements invite.Manager.
func (s *Invites) ListUsable(ctx context.Context, now time.Time) ([]*invite.Invite, error) {
	rows, err := s.db.Query(ctx, `SELECT `+inviteCols+` FROM iam_invites
		 WHERE used_at IS NULL AND expires_at > $1
		 ORDER BY created_at DESC, id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*invite.Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// DeleteUsable implements invite.Manager with a conditional DELETE.
func (s *Invites) DeleteUsable(ctx context.Context, id string, now time.Time) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM iam_invites WHERE id = $1 AND used_at IS NULL AND expires_at > $2`, id, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	var exists bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM iam_invites WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return invite.ErrInvalid
	}
	return invite.ErrNotFound
}

// Replace implements invite.Manager in one transaction.
func (s *Invites) Replace(ctx context.Context, oldID string, now time.Time, inv *invite.Invite) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	// Rollback after Commit is a no-op that returns pgx.ErrTxClosed.
	defer func() { _ = tx.Rollback(ctx) }()
	in := &Invites{db: tx}
	if err := in.DeleteUsable(ctx, oldID, now); err != nil {
		return err
	}
	if err := in.Create(ctx, inv); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
