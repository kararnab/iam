package policy_test

import (
	"context"
	"fmt"

	"github.com/kararnab/iam/v2/policy"
)

func ExampleNewRBAC() {
	rbac, _ := policy.NewRBAC(map[string][]policy.Permission{
		"admin":  {policy.P(policy.Wildcard, policy.Wildcard)},
		"editor": {policy.P("read", "book"), policy.P("write", "book")},
		"reader": {policy.P("read", "book")},
	})

	reader := policy.SubjectContext{SubjectID: "u1", Roles: []string{"reader"}}
	for _, action := range []policy.Action{"read", "write"} {
		d, _ := rbac.Evaluate(context.Background(), reader, action, policy.Resource{Type: "book"})
		fmt.Printf("%s: %s (%s)\n", action, d.Effect, d.Reason)
	}
	// Output:
	// read: allow (role "reader" grants read on book)
	// write: deny (no role grants write on book)
}

// Editors may write any book; everyone else only the books they own.
func ExampleAnyOf() {
	rbac, _ := policy.NewRBAC(map[string][]policy.Permission{
		"editor": {policy.P("write", "book")},
	})
	owner := policy.Func(func(_ context.Context, s policy.SubjectContext, _ policy.Action, r policy.Resource) (*policy.Decision, error) {
		if r.Attrs["owner_id"] == s.SubjectID {
			return policy.Allow("owner"), nil
		}
		return policy.Deny("not the owner"), nil
	})
	engine := policy.AnyOf(rbac, owner)

	book := policy.Resource{Type: "book", ID: "42", Attrs: map[string]string{"owner_id": "ana"}}
	for _, who := range []string{"ana", "bob"} {
		d, _ := engine.Evaluate(context.Background(), policy.SubjectContext{SubjectID: who}, "write", book)
		fmt.Println(who, d.Allowed())
	}
	// Output:
	// ana true
	// bob false
}
