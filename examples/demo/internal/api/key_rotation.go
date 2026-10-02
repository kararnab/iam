package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/kararnab/iam/token/keys"
)

type KeyRotationHandler struct {
	Keys *keys.MemoryProvider
}

func NewKeyRotationHandler(kp *keys.MemoryProvider) *KeyRotationHandler {
	return &KeyRotationHandler{Keys: kp}
}

func (h *KeyRotationHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	// TODO:
	//   - Enforce admin-only policy
	//   - Audit event
	//   - External KMS integration

	newKey := make([]byte, 32)
	if _, err := rand.Read(newKey); err != nil {
		http.Error(w, "failed to generate key", http.StatusInternalServerError)
		return
	}

	prev := h.Keys.ActiveKey()

	newKeyID := prev.ID + "-rotated" // TODO: better ID scheme

	h.Keys.Rotate(keys.Key{
		ID:  newKeyID,
		Key: newKey,
	})

	writeJSON(w, http.StatusOK, map[string]string{
		"status":            "rotated",
		"active_key_id":     newKeyID,
		"previous_key_id":   prev.ID,
		"active_key_base64": base64.StdEncoding.EncodeToString(newKey), // ⚠️ REMOVE IN PROD
	})
}

// ⚠️ Important
// The base64 key is returned only for demo/debug.
// In real systems, keys go to Vault/KMS, never over HTTP.
