package api

import (
	"crypto/rand"
	"net/http"

	"github.com/kararnab/iam/v2/token/keys"
)

type KeyRotationHandler struct {
	Keys *keys.MemoryProvider
}

func NewKeyRotationHandler(kp *keys.MemoryProvider) *KeyRotationHandler {
	return &KeyRotationHandler{Keys: kp}
}

// Rotate generates a new signing key and makes it active. Tokens signed with
// the previous key keep verifying until it is pruned.
//
// Key material is never returned over HTTP. In real systems keys come from a
// KMS or Vault; this endpoint exists to demonstrate rotation.
func (h *KeyRotationHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	secret := make([]byte, keys.MinHMACKeySize)
	if _, err := rand.Read(secret); err != nil {
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}

	prev := h.Keys.ActiveKey()
	next := keys.Key{
		ID:     "k-" + rand.Text()[:12],
		Alg:    prev.Alg,
		Secret: secret,
	}

	if err := h.Keys.Rotate(next); err != nil {
		http.Error(w, "rotation failed", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":          "rotated",
		"active_key_id":   next.ID,
		"previous_key_id": prev.ID,
	})
}
