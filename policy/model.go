package policy

// Effect represents the result of a policy evaluation.
type Effect string

const (
	// EffectAllow indicates the action is permitted.
	EffectAllow Effect = "allow"

	// EffectDeny indicates the action is explicitly denied.
	EffectDeny Effect = "deny"
)

// Decision represents the outcome of an authorization check.
//
// This structure is intentionally simple so it can be:
//   - logged
//   - audited
//   - returned in debug / dry-run modes
type Decision struct {
	Effect Effect
	Reason string // optional human-readable explanation
}

// SubjectContext represents the identity context used for policy evaluation.
//
// This is derived from IAM Subject + token claims.
type SubjectContext struct {
	SubjectID string
	Roles     []string
	Attrs     map[string]string
}

// ResourceContext represents the target of an authorization decision.
//
// IAM does NOT interpret resource semantics.
// It simply passes context to the policy engine.
type ResourceContext struct {
	Type  string            // e.g. "book", "order", "invoice", "admin
	ID    string            // optional resource identifier
	Attrs map[string]string // resource-specific attributes
}

// Action represents an operation being attempted on a resource.
type Action string
