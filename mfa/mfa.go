// Package mfa implements time-based one-time passwords (TOTP, RFC 6238)
// and recovery codes, and defines the Store that keeps a subject's factor.
//
// Codes use the parameters every authenticator app supports: HMAC-SHA1,
// 6 digits, 30-second steps. IAM seals TOTP secrets before they reach the
// Store (see iam.MFAConfig.Key), and stores recovery codes only as SHA-256
// hashes.
package mfa

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: HMAC-SHA1 is what RFC 6238 and authenticator apps use; it is not used as a plain hash
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a TOTP code.
	Digits = 6

	// Period is the length of a TOTP time step.
	Period = 30 * time.Second

	// SecretSize is the size of a new TOTP secret (160 bits, RFC 4226).
	SecretSize = 20

	// RecoveryCodeCount is how many recovery codes are issued at a time.
	RecoveryCodeCount = 10
)

var (
	// ErrNotFound is returned by stores when a subject has no factor.
	ErrNotFound = errors.New("mfa: not found")

	b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
)

// NewSecret returns a new random TOTP secret.
func NewSecret() []byte {
	b := make([]byte, SecretSize)
	_, _ = rand.Read(b) // never fails (crypto/rand, Go 1.24+)
	return b
}

// EncodeSecret returns the base32 form users type into authenticator apps.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// DecodeSecret parses the base32 form (as EncodeSecret produces, or as a
// user types it: case and spaces do not matter).
func DecodeSecret(s string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.ReplaceAll(s, " ", "")))
}

// URI returns the otpauth:// URI for a QR code. issuer names your
// application; account names the user (usually their email address).
func URI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{
		"secret":    {EncodeSecret(secret)},
		"issuer":    {issuer},
		"algorithm": {"SHA1"},
		"digits":    {fmt.Sprint(Digits)},
		"period":    {fmt.Sprint(int(Period.Seconds()))},
	}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Step returns the TOTP time step of t.
func Step(t time.Time) int64 { return t.Unix() / int64(Period.Seconds()) }

// Code returns the TOTP code for a time step.
func Code(secret []byte, step int64) string {
	mac := hmac.New(sha1.New, secret)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // G115: steps are positive
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, n%1_000_000)
}

// Validate checks a code against the steps around now (skew steps either
// side) and returns the matching step. It compares in constant time and
// does not prevent replay: the caller must only accept a step greater than
// the last one used (Store.AdvanceTOTP).
func Validate(secret []byte, code string, now time.Time, skew int) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	cur := Step(now)
	var found int64
	ok := 0
	for d := -int64(skew); d <= int64(skew); d++ {
		match := subtle.ConstantTimeCompare([]byte(Code(secret, cur+d)), []byte(code))
		if match == 1 && ok == 0 {
			found = cur + d
		}
		ok |= match
	}
	return found, ok == 1
}

// NewRecoveryCodes returns RecoveryCodeCount new recovery codes, to show
// the user once, and their hashes, to store. Each code has 50 random bits,
// formatted "xxxxx-xxxxx".
func NewRecoveryCodes() (codes []string, hashes [][]byte) {
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	for range RecoveryCodeCount {
		b := make([]byte, 7)
		_, _ = rand.Read(b)
		s := enc.EncodeToString(b)[:10]
		codes = append(codes, s[:5]+"-"+s[5:])
		hashes = append(hashes, HashRecoveryCode(s))
	}
	return codes, hashes
}

// HashRecoveryCode normalizes a recovery code as typed (case, spaces and
// dashes do not matter) and returns its hash.
func HashRecoveryCode(code string) []byte {
	norm := strings.Map(func(r rune) rune {
		switch {
		case r == '-' || r == ' ':
			return -1
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		}
		return r
	}, code)
	sum := sha256.Sum256([]byte("iam-recovery-v1:" + norm))
	return sum[:]
}

// TOTP is a subject's TOTP factor as stored.
type TOTP struct {
	SubjectID string

	// Secret is the sealed secret: opaque to stores, never the raw key.
	Secret []byte

	// Confirmed is false between enrollment and the first valid code. Only
	// confirmed factors are required at login.
	Confirmed bool

	// LastStep is the last time step accepted, for replay protection.
	LastStep int64

	// RecoveryCodes are the SHA-256 hashes of the unused recovery codes.
	RecoveryCodes [][]byte

	CreatedAt time.Time
}

// Store persists TOTP factors, one per subject. Implementations must be
// safe for concurrent use; AdvanceTOTP and UseRecoveryCode must be atomic.
type Store interface {
	// GetTOTP returns the subject's factor, or ErrNotFound.
	GetTOTP(ctx context.Context, subjectID string) (*TOTP, error)

	// PutTOTP creates or replaces the subject's factor.
	PutTOTP(ctx context.Context, t *TOTP) error

	// DeleteTOTP removes the subject's factor. Missing is not an error.
	DeleteTOTP(ctx context.Context, subjectID string) error

	// AdvanceTOTP sets LastStep to step only if step is greater than the
	// stored LastStep, and reports whether it did. Of two concurrent calls
	// with the same step, at most one returns true.
	AdvanceTOTP(ctx context.Context, subjectID string, step int64) (bool, error)

	// UseRecoveryCode removes one recovery-code hash and reports whether
	// it was present. Of two concurrent calls, at most one returns true.
	UseRecoveryCode(ctx context.Context, subjectID string, hash []byte) (bool, error)
}
