// Package password hashes and verifies passwords.
//
// New hashes use argon2id in the PHC string format:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//
// bcrypt hashes ($2a$, $2b$, $2y$) are accepted for verification only, so
// existing users can be migrated: after a successful login, NeedsRehash
// reports true and the caller stores a fresh argon2id hash.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Hasher hashes and verifies passwords.
type Hasher interface {
	// Hash returns an encoded hash of password.
	Hash(ctx context.Context, password string) (string, error)

	// Verify reports whether password matches encoded. A malformed encoded
	// hash is an error; a wrong password is (false, nil).
	Verify(ctx context.Context, password, encoded string) (bool, error)

	// NeedsRehash reports whether encoded should be replaced by a new Hash,
	// because it uses another algorithm or other parameters.
	NeedsRehash(encoded string) bool
}

// Params are argon2id parameters.
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32 // bytes
	KeyLength   uint32 // bytes
}

// DefaultParams is the OWASP baseline for argon2id (19 MiB, t=2, p=1).
var DefaultParams = Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

// Limits on parameters read from stored hashes, so a corrupted or hostile
// record cannot make verification allocate unbounded memory or CPU.
const (
	maxMemory     = 1 << 20 // 1 GiB in KiB
	maxIterations = 64
	maxKeyLength  = 128
	maxSaltLength = 64
)

var (
	// ErrMalformedHash is returned for encoded hashes that cannot be parsed.
	ErrMalformedHash = errors.New("password: malformed hash")

	b64 = base64.RawStdEncoding.Strict()
)

// Argon2id is the default Hasher.
type Argon2id struct {
	params Params
	sem    chan struct{}
}

var _ Hasher = (*Argon2id)(nil)

// NewArgon2id returns an argon2id hasher. maxConcurrent bounds how many hash
// computations run at once (each uses params.Memory KiB); zero means
// GOMAXPROCS.
func NewArgon2id(params Params, maxConcurrent int) (*Argon2id, error) {
	if err := params.validate(); err != nil {
		return nil, err
	}
	if maxConcurrent <= 0 {
		maxConcurrent = runtime.GOMAXPROCS(0)
	}
	return &Argon2id{params: params, sem: make(chan struct{}, maxConcurrent)}, nil
}

func (p Params) validate() error {
	switch {
	case p.Memory < 8*uint32(p.Parallelism) || p.Memory > maxMemory:
		return fmt.Errorf("password: memory must be between 8*parallelism and %d KiB", maxMemory)
	case p.Iterations < 1 || p.Iterations > maxIterations:
		return fmt.Errorf("password: iterations must be between 1 and %d", maxIterations)
	case p.Parallelism < 1:
		return errors.New("password: parallelism must be at least 1")
	case p.SaltLength < 16 || p.SaltLength > maxSaltLength:
		return fmt.Errorf("password: salt length must be between 16 and %d", maxSaltLength)
	case p.KeyLength < 16 || p.KeyLength > maxKeyLength:
		return fmt.Errorf("password: key length must be between 16 and %d", maxKeyLength)
	}
	return nil
}

func (a *Argon2id) acquire(ctx context.Context) error {
	select {
	case a.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Argon2id) release() { <-a.sem }

// Hash implements Hasher.
func (a *Argon2id) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, a.params.SaltLength)
	_, _ = rand.Read(salt)

	if err := a.acquire(ctx); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, a.params.Iterations, a.params.Memory, a.params.Parallelism, a.params.KeyLength)
	a.release()

	return encode(a.params, salt, key), nil
}

// Verify implements Hasher.
func (a *Argon2id) Verify(ctx context.Context, password, encoded string) (bool, error) {
	if isBcrypt(encoded) {
		if err := a.acquire(ctx); err != nil {
			return false, err
		}
		defer a.release()
		err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword), errors.Is(err, bcrypt.ErrPasswordTooLong):
			return false, nil
		default:
			return false, ErrMalformedHash
		}
	}

	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, err
	}
	if err := a.acquire(ctx); err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	a.release()

	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash implements Hasher.
func (a *Argon2id) NeedsRehash(encoded string) bool {
	p, salt, _, err := decode(encoded)
	if err != nil {
		return true
	}
	return p.Memory != a.params.Memory || p.Iterations != a.params.Iterations ||
		p.Parallelism != a.params.Parallelism || p.KeyLength != a.params.KeyLength ||
		uint32(len(salt)) != a.params.SaltLength //nolint:gosec // G115: decode bounds the salt to maxSaltLength (64)
}

func isBcrypt(encoded string) bool {
	return strings.HasPrefix(encoded, "$2a$") || strings.HasPrefix(encoded, "$2b$") || strings.HasPrefix(encoded, "$2y$")
}

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

// decode parses a PHC argon2id string strictly.
func decode(encoded string) (Params, []byte, []byte, error) {
	var p Params
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrMalformedHash
	}
	if parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return p, nil, nil, ErrMalformedHash
	}

	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return p, nil, nil, ErrMalformedHash
	}
	m, ok1 := parseUint(kv[0], "m=", maxMemory)
	t, ok2 := parseUint(kv[1], "t=", maxIterations)
	par, ok3 := parseUint(kv[2], "p=", 255)
	if !ok1 || !ok2 || !ok3 || t < 1 || par < 1 || m < 8*par {
		return p, nil, nil, ErrMalformedHash
	}

	// The base64 decoder skips CR/LF even in strict mode, so require the
	// canonical encoding by round-tripping.
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > maxSaltLength || b64.EncodeToString(salt) != parts[4] {
		return p, nil, nil, ErrMalformedHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > maxKeyLength || b64.EncodeToString(key) != parts[5] {
		return p, nil, nil, ErrMalformedHash
	}

	//nolint:gosec // G115: par <= 255, salt <= 64 and key <= 128 bytes are checked above
	p = Params{Memory: m, Iterations: t, Parallelism: uint8(par), SaltLength: uint32(len(salt)), KeyLength: uint32(len(key))}
	return p, salt, key, nil
}

// parseUint parses "<prefix><digits>" with no sign, no leading zeros and
// value <= max.
func parseUint(s, prefix string, max uint32) (uint32, bool) {
	digits, ok := strings.CutPrefix(s, prefix)
	if !ok || digits == "" || len(digits) > 10 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || n > uint64(max) {
		return 0, false
	}
	return uint32(n), true
}

// Policy holds password length rules. Lengths are counted in Unicode
// characters for the minimum and bytes for the maximum (which only exists to
// bound hashing cost).
type Policy struct {
	MinLength int // characters; DefaultPolicy uses 12
	MaxLength int // bytes; DefaultPolicy uses 1024
}

// DefaultPolicy follows NIST SP 800-63B guidance: length over composition rules.
var DefaultPolicy = Policy{MinLength: 12, MaxLength: 1024}

var (
	// ErrTooShort is returned by Policy.Check.
	ErrTooShort = errors.New("password: too short")
	// ErrTooLong is returned by Policy.Check.
	ErrTooLong = errors.New("password: too long")
)

// Check validates a new password against the policy.
func (p Policy) Check(password string) error {
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		return ErrTooLong
	}
	if utf8.RuneCountInString(password) < p.MinLength {
		return ErrTooShort
	}
	return nil
}
