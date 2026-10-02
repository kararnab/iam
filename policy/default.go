package policy

import "context"

// DefaultPolicy is the MVP authorization engine.
//
// Rules:
//   - Admin resources require "admin" role
//   - All other resources are allowed (MVP)
//
// TODO (prod):
//   - Deny-by-default
//   - RBAC / ABAC
//   - Policy versioning
type DefaultPolicy struct{}

const (
	Admin = "admin"
)

func (p *DefaultPolicy) Evaluate(
	ctx context.Context,
	subject SubjectContext,
	action Action,
	resource ResourceContext,
) (*Decision, error) {

	// -------------------------------
	// Admin-only resources
	// -------------------------------
	if resource.Type == Admin {
		for _, role := range subject.Roles {
			if role == Admin {
				return allow(Admin + " role")
			}
		}
		return deny(Admin + " role required")
	}

	// -------------------------------
	// Default MVP behavior
	// -------------------------------
	return allow("default allow (mvp)")
}

func allow(reason string) (*Decision, error) {
	return &Decision{
		Effect: EffectAllow,
		Reason: reason,
	}, nil
}

func deny(reason string) (*Decision, error) {
	return &Decision{
		Effect: EffectDeny,
		Reason: reason,
	}, nil
}
