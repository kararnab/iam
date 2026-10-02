package api

import "github.com/kararnab/iam/v2/policy"

// Demo roles, actions and resource types.
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleReader = "reader"

	ActionRead   policy.Action = "read"
	ActionWrite  policy.Action = "write"
	ActionRotate policy.Action = "rotate"
	ActionCreate policy.Action = "create"

	ResourceBook       = "book"
	ResourceSigningKey = "signing_key"
	ResourceInvite     = "invite"
)

// NewPolicy returns the demo's RBAC policy. Anything not listed is denied.
func NewPolicy() (*policy.RBAC, error) {
	return policy.NewRBAC(map[string][]policy.Permission{
		RoleAdmin:  {policy.P(policy.Wildcard, policy.Wildcard)},
		RoleEditor: {policy.P(ActionRead, ResourceBook), policy.P(ActionWrite, ResourceBook)},
		RoleReader: {policy.P(ActionRead, ResourceBook)},
	})
}
