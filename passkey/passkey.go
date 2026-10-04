// Package passkey defines stored WebAuthn credentials (passkeys and
// security keys) and the Store that keeps them.
//
// The ceremonies (registration and login) live in the webauthn module
// (github.com/kararnab/iam/webauthn/v2), so the core stays free of their
// dependencies. Credentials hold only public keys.
package passkey

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrNotFound is returned by stores for missing credentials.
	ErrNotFound = errors.New("passkey: not found")

	// ErrConflict is returned by Store.Create for a credential ID that
	// already exists.
	ErrConflict = errors.New("passkey: credential already exists")
)

// Credential is a registered WebAuthn credential.
type Credential struct {
	ID        []byte // credential ID chosen by the authenticator
	SubjectID string
	Name      string // a label for the user ("MacBook", "YubiKey")

	PublicKey         []byte // COSE public key
	AttestationType   string
	AttestationFormat string
	AAGUID            []byte   // authenticator model, when attested
	Transports        []string // usb, nfc, ble, internal, hybrid
	SignCount         uint32

	UserPresent    bool
	UserVerified   bool
	BackupEligible bool // a synced passkey (never changes)
	BackupState    bool // currently backed up (may change)

	CreatedAt  time.Time
	LastUsedAt time.Time // zero until first used to sign in
}

// Store persists credentials. Implementations must be safe for concurrent
// use.
type Store interface {
	// Create persists a new credential, or returns ErrConflict.
	Create(ctx context.Context, c *Credential) error

	// Get returns a credential by ID, or ErrNotFound.
	Get(ctx context.Context, id []byte) (*Credential, error)

	// ListBySubject returns a subject's credentials, oldest first.
	ListBySubject(ctx context.Context, subjectID string) ([]*Credential, error)

	// Touch records a sign-in: the new signature counter, backup state and
	// time. Missing is ErrNotFound.
	Touch(ctx context.Context, id []byte, signCount uint32, backupState bool, at time.Time) error

	// Delete removes one of the subject's credentials. Missing (or another
	// subject's) is not an error.
	Delete(ctx context.Context, subjectID string, id []byte) error
}
