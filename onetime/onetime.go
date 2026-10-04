// Package onetime defines single-use, expiring tokens for account actions:
// password reset and email verification.
//
// A token is a 256-bit random secret handed to the application once, to
// deliver (IAM sends no email). Stores keep only its SHA-256 hash, exactly
// like session secrets and invites.
package onetime

import (
	"context"
	"errors"
	"time"
)

// Purpose says what a token may be used for. A token never works for
// another purpose.
type Purpose string

const (
	// PasswordReset tokens let the holder set a new password for Login.
	PasswordReset Purpose = "password_reset"

	// EmailVerification tokens prove that the holder receives mail at Email.
	EmailVerification Purpose = "email_verification"
)

// Valid reports whether p is a known purpose.
func (p Purpose) Valid() bool { return p == PasswordReset || p == EmailVerification }

var (
	// ErrInvalid is returned for unknown, used or expired tokens, and for a
	// token presented for another purpose.
	ErrInvalid = errors.New("onetime: invalid, used or expired token")

	// ErrNotFound is returned by stores for missing tokens.
	ErrNotFound = errors.New("onetime: not found")
)

// Token is the stored record. It never contains the secret.
type Token struct {
	ID        string // public identifier, for audit
	TokenHash []byte // SHA-256 of the secret
	Purpose   Purpose
	SubjectID string // the subject the action applies to

	Login string // PasswordReset: the password login (provider ID)
	Email string // EmailVerification: the address being verified

	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time // zero until consumed
}

// Usable reports whether the token can still be consumed at now.
func (t *Token) Usable(now time.Time) bool {
	return t.UsedAt.IsZero() && now.Before(t.ExpiresAt)
}

// Store persists tokens. Implementations must be safe for concurrent use,
// and Consume must be atomic: of two concurrent calls for the same hash, at
// most one succeeds.
type Store interface {
	// Create persists a new token. The ID and TokenHash are unique.
	Create(ctx context.Context, t *Token) error

	// GetByTokenHash returns a token (used or not), or ErrNotFound.
	GetByTokenHash(ctx context.Context, hash []byte) (*Token, error)

	// Consume marks the token as used at time at, but only if it has this
	// purpose and is still usable at that time; otherwise ErrInvalid.
	Consume(ctx context.Context, hash []byte, purpose Purpose, at time.Time) (*Token, error)

	// DeleteBySubject removes a subject's tokens of one purpose, used or
	// not. A new request supersedes older ones this way.
	DeleteBySubject(ctx context.Context, subjectID string, purpose Purpose) error
}
