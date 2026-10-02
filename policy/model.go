package policy

// Effect represents the result of a policy evaluation.
type Effect string

const (
	// EffectAllow indicates the action is permitted.
	EffectAllow Effect = "allow"

	// EffectDeny indicates the action is denied.
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
	Reason string // human-readable explanation; never shown to end users verbatim
}

// Allowed reports whether d is an allow decision. A nil decision is a deny.
func (d *Decision) Allowed() bool { return d != nil && d.Effect == EffectAllow }

// Allow returns an allow decision.
func Allow(reason string) *Decision { return &Decision{Effect: EffectAllow, Reason: reason} }

// Deny returns a deny decision.
func Deny(reason string) *Decision { return &Decision{Effect: EffectDeny, Reason: reason} }

// SubjectContext represents the identity context used for policy evaluation.
//
// This is derived from IAM Subject + token claims.
type SubjectContext struct {
	SubjectID string
	Roles     []string
	Attrs     map[string]string
}

// Resource represents the target of an authorization decision.
//
// IAM does NOT interpret resource semantics.
// It simply passes context to the policy engine.
type Resource struct {
	Type  string            // e.g. "book", "order", "invoice"
	ID    string            // optional resource identifier
	Attrs map[string]string // resource-specific attributes (owner_id, ...)
}

// Action represents an operation being attempted on a resource.
type Action string

// Wildcard matches any action or resource type in a Permission.
const Wildcard = "*"
