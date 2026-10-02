package keys

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Alg names the algorithm a key is pinned to. A key is only ever used with
// its own algorithm; the algorithm named inside a token is never trusted.
type Alg string

const (
	// HS256 is HMAC-SHA256 (JWT). Secret must be at least MinHMACKeySize bytes.
	HS256 Alg = "HS256"

	// EdDSA is Ed25519 (JWT). PublicKey is required; PrivateKey is required
	// only for issuing.
	EdDSA Alg = "EdDSA"
)

// MinHMACKeySize is the minimum HMAC secret length (256 bits).
const MinHMACKeySize = 32

// Key represents a cryptographic key usable for issuing or verifying tokens.
type Key struct {
	ID  string // logical key ID (kid); must be unique per provider
	Alg Alg    // pinned algorithm; token formats may define their own values

	Secret     []byte             // symmetric key material (HS256, PASETO local)
	PrivateKey ed25519.PrivateKey // EdDSA signing key
	PublicKey  ed25519.PublicKey  // EdDSA verification key
}

// ValidateForJWT reports whether k is usable for JWT signing (sign=true)
// or verification (sign=false).
func (k Key) ValidateForJWT(sign bool) error {
	if k.ID == "" {
		return errors.New("keys: key ID is required")
	}
	switch k.Alg {
	case HS256:
		if len(k.Secret) < MinHMACKeySize {
			return fmt.Errorf("keys: HS256 key %q must be at least %d bytes", k.ID, MinHMACKeySize)
		}
	case EdDSA:
		if len(k.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("keys: EdDSA key %q has no valid public key", k.ID)
		}
		if sign && len(k.PrivateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("keys: EdDSA key %q has no valid private key", k.ID)
		}
	default:
		return fmt.Errorf("keys: key %q has unsupported JWT algorithm %q", k.ID, k.Alg)
	}
	return nil
}

// Provider exposes active and historical keys.
//
// Contract:
//   - ActiveKey() is used ONLY for issuing tokens, and is read on every issue
//     so that rotation takes effect immediately
//   - VerificationKeys() is used for verification
//   - VerificationKeys MUST include ActiveKey
//   - implementations must be safe for concurrent use
type Provider interface {
	ActiveKey() Key
	VerificationKeys() []Key
}

// Find returns the verification key with the given ID.
func Find(p Provider, id string) (Key, bool) {
	for _, k := range p.VerificationKeys() {
		if k.ID == id {
			return k, true
		}
	}
	return Key{}, false
}
