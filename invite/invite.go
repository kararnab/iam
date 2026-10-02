// Package invite defines single-use, expiring sign-up invitations.
//
// The invite token is a 256-bit random secret handed to the invitee once.
// Stores keep only its SHA-256 hash, exactly like session secrets.
package invite

import (
	"context"
	"errors"
	"time"
)

// Policy controls who may sign up.
type Policy string

const (
	// Closed: nobody may sign up; subjects are created by the application.
	Closed Policy = "closed"

	// InviteOnly: sign-up requires a valid invite. The default.
	InviteOnly Policy = "invite_only"

	// Open: anyone may sign up.
	Open Policy = "open"
)

var (
	// ErrInvalid is returned for unknown, used, expired or mismatched invites.
	ErrInvalid = errors.New("invite: invalid, used or expired")

	// ErrNotFound is returned by stores for missing invites.
	ErrNotFound = errors.New("invite: not found")
)

// Invite is the stored record. It never contains the token.
type Invite struct {
	ID        string // public identifier
	TokenHash []byte // SHA-256 of the token

	Email     string   // optional; if set, the signing-up identity must have this email
	Roles     []string // granted to the new subject (via iam.SignupGrant)
	CreatedBy string   // subject ID of the inviter (for audit)

	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time // zero until consumed
	UsedBy    string    // identity that used it, as "provider:providerID"
}

// Usable reports whether the invite can still be consumed at now.
func (i *Invite) Usable(now time.Time) bool {
	return i.UsedAt.IsZero() && now.Before(i.ExpiresAt)
}

// Store persists invites. Consume must be atomic: of two concurrent calls
// for the same hash, at most one succeeds.
type Store interface {
	// Create persists a new invite.
	Create(ctx context.Context, inv *Invite) error

	// GetByTokenHash returns an invite (used or not), or ErrNotFound.
	GetByTokenHash(ctx context.Context, hash []byte) (*Invite, error)

	// Consume marks the invite as used by usedBy at time at, but only if it
	// is still usable at that time; otherwise ErrInvalid.
	Consume(ctx context.Context, hash []byte, usedBy string, at time.Time) (*Invite, error)

	// Delete removes an invite (revocation). Missing is not an error.
	Delete(ctx context.Context, id string) error
}
