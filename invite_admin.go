package iam

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/kararnab/iam/v2/audit"
	"github.com/kararnab/iam/v2/invite"
)

// ErrInvitesNotManaged is returned by InviteAdmin methods when invites are
// not configured, or when Config.Signup.Invites does not implement
// invite.Manager.
var ErrInvitesNotManaged = errors.New("iam: the invite store does not support invite management (invite.Manager)")

// InviteAdmin manages pending invites, for an administration screen. The
// Service returned by New implements it, and NewServices returns it typed.
// The methods need Config.Signup.Invites to implement invite.Manager
// (memstore and pgstore do); otherwise they return ErrInvitesNotManaged.
//
// Like CreateInvite, these methods do not authorize the caller: the
// application checks that the caller may manage invites first.
type InviteAdmin interface {
	// ListPendingInvites returns the invites that can still be used, newest
	// first. It never returns a token.
	ListPendingInvites(ctx context.Context) ([]PendingInvite, error)

	// RevokePendingInvite deletes an invite that can still be used. It
	// returns ErrNotFound for an unknown invite and ErrInvalidInvite for a
	// used or expired one, which it keeps.
	RevokePendingInvite(ctx context.Context, inviteID string, revokedBy string) error

	// ReplaceInvite revokes a pending invite and issues a new one from req
	// in one step, so that only the new link works ("send again"). Errors
	// for the old invite are as for RevokePendingInvite; then nothing is
	// issued. Of two concurrent replacements of one invite, at most one
	// succeeds.
	ReplaceInvite(ctx context.Context, inviteID string, req InviteRequest) (*IssuedInvite, error)
}

// PendingInvite describes a usable invite, without its token.
type PendingInvite struct {
	ID        string    `json:"id"`
	Email     string    `json:"email,omitempty"`
	Roles     []string  `json:"roles,omitempty"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

var _ InviteAdmin = (*service)(nil)

func (s *service) inviteManager() (invite.Manager, error) {
	m, ok := s.cfg.Signup.Invites.(invite.Manager)
	if !ok {
		return nil, ErrInvitesNotManaged
	}
	return m, nil
}

func (s *service) ListPendingInvites(ctx context.Context) ([]PendingInvite, error) {
	m, err := s.inviteManager()
	if err != nil {
		return nil, err
	}
	list, err := m.ListUsable(ctx, s.cfg.Now())
	if err != nil {
		return nil, err
	}
	out := make([]PendingInvite, 0, len(list))
	for _, inv := range list {
		out = append(out, PendingInvite{
			ID:        inv.ID,
			Email:     inv.Email,
			Roles:     slices.Clone(inv.Roles),
			CreatedBy: inv.CreatedBy,
			CreatedAt: inv.CreatedAt,
			ExpiresAt: inv.ExpiresAt,
		})
	}
	return out, nil
}

func (s *service) RevokePendingInvite(ctx context.Context, inviteID, revokedBy string) error {
	m, err := s.inviteManager()
	if err != nil {
		return err
	}
	if err := inviteStoreError(m.DeleteUsable(ctx, inviteID, s.cfg.Now())); err != nil {
		return err
	}
	s.audit(ctx, audit.Event{
		Type:      audit.EventInviteRevoked,
		SubjectID: revokedBy,
		Message:   "invite revoked",
		Attrs:     map[string]string{"invite_id": inviteID},
	})
	return nil
}

func (s *service) ReplaceInvite(ctx context.Context, inviteID string, req InviteRequest) (*IssuedInvite, error) {
	m, err := s.inviteManager()
	if err != nil {
		return nil, err
	}
	inv, tok, err := s.newInvite(req)
	if err != nil {
		return nil, err
	}
	if err := inviteStoreError(m.Replace(ctx, inviteID, s.cfg.Now(), inv)); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{
		Type:      audit.EventInviteRevoked,
		SubjectID: req.CreatedBy,
		Message:   "invite revoked",
		Attrs:     map[string]string{"invite_id": inviteID, "replaced_by": inv.ID},
	})
	s.auditInviteCreated(ctx, inv)
	return &IssuedInvite{ID: inv.ID, Token: tok, ExpiresAt: inv.ExpiresAt}, nil
}

// inviteStoreError maps the invite package's sentinels to iam's.
func inviteStoreError(err error) error {
	switch {
	case errors.Is(err, invite.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, invite.ErrInvalid):
		return ErrInvalidInvite
	}
	return err
}
