package keys

// Key represents a cryptographic key usable for issuing or verifying tokens.
type Key struct {
	ID  string // logical key ID (kid)
	Key []byte // raw key material
}

// Provider exposes active and historical keys.
//
// Contract:
//   - ActiveKey() is used ONLY for issuing tokens
//   - VerificationKeys() is used for verification
//   - VerificationKeys MUST include ActiveKey
type Provider interface {
	ActiveKey() Key
	VerificationKeys() []Key
}
