package iam

import (
	"context"
	"errors"

	"github.com/kararnab/iam/v2/provider"
)

var (
	// ErrNotFound is returned by stores when a record does not exist.
	ErrNotFound = errors.New("iam: not found")

	// ErrConflict is returned by stores when a record already exists.
	ErrConflict = errors.New("iam: already exists")

	// ErrIdentityLinked is returned when a provider identity already
	// belongs to a different subject.
	ErrIdentityLinked = errors.New("iam: identity is linked to another subject")

	// ErrUnknownIdentity is returned when a provider identity is valid but
	// not linked to any subject, and sign-up is not possible.
	ErrUnknownIdentity = errors.New("iam: identity is not linked to a subject")

	// ErrSubjectDisabled is returned when the subject exists but is disabled.
	ErrSubjectDisabled = errors.New("iam: subject is disabled")
)

// SubjectLoader loads a subject by its canonical ID.
//
// It is implemented by the application's user store. IAM calls it on login,
// on every refresh, and (in cookie mode) on every request, so roles and the
// Disabled flag always come from the application.
type SubjectLoader interface {
	// LoadSubject returns ErrNotFound if the subject does not exist.
	LoadSubject(ctx context.Context, subjectID string) (*Subject, error)
}

// IdentityStore maps provider identities to subjects (one subject, many
// identities). It is implemented by the application's user store.
type IdentityStore interface {
	// ResolveIdentity returns the subject linked to (provider, providerID),
	// or ErrNotFound.
	ResolveIdentity(ctx context.Context, provider, providerID string) (subjectID string, err error)

	// LinkIdentity links an identity to a subject. It returns ErrConflict if
	// the identity is already linked (to any subject).
	LinkIdentity(ctx context.Context, subjectID string, id provider.Identity) error

	// UnlinkIdentity removes a link. Unlinking a missing link is not an error.
	UnlinkIdentity(ctx context.Context, subjectID, provider, providerID string) error

	// CreateSubject creates a new subject for a first-time identity and
	// returns its canonical ID. It must NOT link the identity; IAM calls
	// LinkIdentity afterwards. It is only called when sign-up is allowed.
	CreateSubject(ctx context.Context, id provider.Identity, grant SignupGrant) (subjectID string, err error)
}

// SignupGrant carries what a sign-up is entitled to, for example roles from
// an invite, plus the application's own profile fields. The application
// decides how to apply it.
type SignupGrant struct {
	Roles    []string
	InviteID string

	// Profile is SignUpRequest.Profile, passed through untouched: fields
	// from the sign-up form (display name, locale, ...) that the store can
	// save in the same write that creates the subject. IAM never reads it.
	Profile map[string]string
}

// UserStore is the combination IAM needs from the application.
type UserStore interface {
	SubjectLoader
	IdentityStore
}

// SubjectDeleter is optionally implemented by a UserStore. When a sign-up
// fails after CreateSubject succeeded (linking the identity or starting
// the session failed), SignUp calls DeleteSubject so no subject is left
// that nobody can sign in to. Without it such a subject remains, and the
// store has to clean it up itself.
//
// DeleteSubject removes the subject and the identities linked to it.
// Deleting a missing subject is not an error. A consumed invite is not
// restored.
type SubjectDeleter interface {
	DeleteSubject(ctx context.Context, subjectID string) error
}
