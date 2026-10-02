package policy

import (
	"context"
	"errors"
)

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
// Implementations must be deterministic and deny by default: anything not
// explicitly allowed is denied. Returning an error also results in a deny.
type Engine interface {
	Evaluate(
		ctx context.Context,
		subject SubjectContext,
		action Action,
		resource Resource,
	) (*Decision, error)
}

// Func adapts a function to Engine. It is the usual way to add ownership or
// attribute checks, combined with RBAC through AnyOf or AllOf.
type Func func(ctx context.Context, subject SubjectContext, action Action, resource Resource) (*Decision, error)

// Evaluate implements Engine.
func (f Func) Evaluate(ctx context.Context, s SubjectContext, a Action, r Resource) (*Decision, error) {
	return f(ctx, s, a, r)
}

// DenyAll denies everything. Useful as a placeholder and in tests.
var DenyAll Engine = Func(func(context.Context, SubjectContext, Action, Resource) (*Decision, error) {
	return Deny("deny all"), nil
})

// AnyOf allows if at least one engine allows. Engines are evaluated in
// order; an error from any engine evaluated before an allow fails closed.
func AnyOf(engines ...Engine) Engine {
	return Func(func(ctx context.Context, s SubjectContext, a Action, r Resource) (*Decision, error) {
		if len(engines) == 0 {
			return Deny("no engines"), nil
		}
		last := Deny("no engine allowed")
		for _, e := range engines {
			d, err := e.Evaluate(ctx, s, a, r)
			if err != nil {
				return Deny("engine error"), err
			}
			if d.Allowed() {
				return d, nil
			}
			if d != nil {
				last = d
			}
		}
		return last, nil
	})
}

// AllOf allows only if every engine allows. The first deny or error wins.
func AllOf(engines ...Engine) Engine {
	return Func(func(ctx context.Context, s SubjectContext, a Action, r Resource) (*Decision, error) {
		if len(engines) == 0 {
			return Deny("no engines"), nil
		}
		var last *Decision
		for _, e := range engines {
			d, err := e.Evaluate(ctx, s, a, r)
			if err != nil {
				return Deny("engine error"), err
			}
			if !d.Allowed() {
				if d == nil {
					d = Deny("nil decision")
				}
				return d, nil
			}
			last = d
		}
		return last, nil
	})
}

// ErrInvalidPolicy is returned by NewRBAC for malformed configuration.
var ErrInvalidPolicy = errors.New("policy: invalid configuration")
