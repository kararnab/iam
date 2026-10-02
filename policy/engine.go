package policy

import "context"

// Engine defines the contract for authorization decision making.
//
// An Engine evaluates whether a subject can perform an action
// on a given resource under the current context.
//
// The engine:
//   - is invoked AFTER authentication
//   - does NOT authenticate users
//   - does NOT issue tokens
//
// Different implementations may support:
//   - RBAC
//   - ABAC
//   - ReBAC
//   - Hybrid models
type Engine interface {

	// Evaluate returns an authorization decision for a request.
	//
	// Expected behavior:
	//   - Evaluate policies deterministically
	//   - Default-deny if no policy matches
	//
	// TODO:
	//   - Policy versioning
	//   - Policy simulation / dry-run
	//   - Explainable decisions
	Evaluate(
		ctx context.Context,
		subject SubjectContext,
		action Action,
		resource ResourceContext,
	) (*Decision, error)
}
