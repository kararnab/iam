package policy

import (
	"context"
	"fmt"
	"strings"
)

// Permission grants an action on a resource type. Either may be Wildcard.
type Permission struct {
	Action       Action
	ResourceType string
}

// P is shorthand for a Permission.
func P(action Action, resourceType string) Permission {
	return Permission{Action: action, ResourceType: resourceType}
}

func (p Permission) matches(a Action, resourceType string) bool {
	return (p.Action == Wildcard || p.Action == a) &&
		(p.ResourceType == Wildcard || p.ResourceType == resourceType)
}

func (p Permission) String() string { return string(p.Action) + " on " + p.ResourceType }

// RBAC maps roles to permissions on resource types. It denies anything no
// role grants. It does not look at resource IDs or attributes; combine it
// with a Func through AnyOf/AllOf for ownership rules.
type RBAC struct {
	roles map[string][]Permission
}

var _ Engine = (*RBAC)(nil)

// NewRBAC validates and copies the role table.
//
//	policy.NewRBAC(map[string][]policy.Permission{
//	    "admin":  {policy.P("*", "*")},
//	    "editor": {policy.P("read", "book"), policy.P("write", "book")},
//	    "reader": {policy.P("read", "book")},
//	})
func NewRBAC(roles map[string][]Permission) (*RBAC, error) {
	copied := make(map[string][]Permission, len(roles))
	for role, perms := range roles {
		if strings.TrimSpace(role) == "" {
			return nil, fmt.Errorf("%w: empty role name", ErrInvalidPolicy)
		}
		for _, p := range perms {
			if p.Action == "" || p.ResourceType == "" {
				return nil, fmt.Errorf("%w: role %q has an empty action or resource type", ErrInvalidPolicy, role)
			}
		}
		copied[role] = append([]Permission(nil), perms...)
	}
	return &RBAC{roles: copied}, nil
}

// Evaluate implements Engine.
func (r *RBAC) Evaluate(_ context.Context, s SubjectContext, a Action, res Resource) (*Decision, error) {
	if a == "" || res.Type == "" {
		return Deny("empty action or resource type"), nil
	}
	for _, role := range s.Roles {
		for _, p := range r.roles[role] {
			if p.matches(a, res.Type) {
				return Allow(fmt.Sprintf("role %q grants %s", role, p)), nil
			}
		}
	}
	return Deny(fmt.Sprintf("no role grants %s on %s", a, res.Type)), nil
}

// Grants reports whether role grants action on resourceType, for building
// UIs (for example to hide buttons). Authorization must still go through
// Evaluate.
func (r *RBAC) Grants(role string, a Action, resourceType string) bool {
	for _, p := range r.roles[role] {
		if p.matches(a, resourceType) {
			return true
		}
	}
	return false
}
