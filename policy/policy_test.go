package policy

import (
	"context"
	"errors"
	"testing"
)

var ctx = context.Background()

func mustRBAC(t *testing.T) *RBAC {
	t.Helper()
	r, err := NewRBAC(map[string][]Permission{
		"admin":   {P(Wildcard, Wildcard)},
		"editor":  {P("read", "book"), P("write", "book")},
		"reader":  {P("read", "book")},
		"auditor": {P("read", Wildcard)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestRBAC(t *testing.T) {
	r := mustRBAC(t)
	tests := []struct {
		name   string
		roles  []string
		action Action
		typ    string
		allow  bool
	}{
		{"admin anything", []string{"admin"}, "delete", "invoice", true},
		{"editor writes books", []string{"editor"}, "write", "book", true},
		{"reader reads books", []string{"reader"}, "read", "book", true},
		{"reader cannot write", []string{"reader"}, "write", "book", false},
		{"reader cannot read other types", []string{"reader"}, "read", "invoice", false},
		{"wildcard resource type", []string{"auditor"}, "read", "invoice", true},
		{"wildcard does not widen action", []string{"auditor"}, "write", "invoice", false},
		{"any matching role", []string{"reader", "editor"}, "write", "book", true},
		{"no roles", nil, "read", "book", false},
		{"unknown role", []string{"root"}, "read", "book", false},
		{"empty action denied even for admin", []string{"admin"}, "", "book", false},
		{"empty resource type denied", []string{"admin"}, "read", "", false},
		{"literal star action is not a wildcard request", []string{"reader"}, Wildcard, "book", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := r.Evaluate(ctx, SubjectContext{Roles: tt.roles}, tt.action, Resource{Type: tt.typ})
			if err != nil {
				t.Fatal(err)
			}
			if d.Allowed() != tt.allow {
				t.Fatalf("decision = %+v, want allow=%v", d, tt.allow)
			}
			if d.Reason == "" {
				t.Fatal("decision has no reason")
			}
		})
	}
}

func TestRBACGrants(t *testing.T) {
	r := mustRBAC(t)
	if !r.Grants("editor", "write", "book") || r.Grants("reader", "write", "book") {
		t.Fatal("Grants disagrees with the role table")
	}
}

func TestNewRBACValidates(t *testing.T) {
	bad := []map[string][]Permission{
		{"": {P("read", "book")}},
		{"reader": {P("", "book")}},
		{"reader": {P("read", "")}},
	}
	for _, roles := range bad {
		if _, err := NewRBAC(roles); !errors.Is(err, ErrInvalidPolicy) {
			t.Errorf("NewRBAC(%v) err = %v", roles, err)
		}
	}
}

func TestNewRBACCopiesInput(t *testing.T) {
	perms := []Permission{P("read", "book")}
	r, _ := NewRBAC(map[string][]Permission{"reader": perms})
	perms[0] = P(Wildcard, Wildcard)
	if r.Grants("reader", "delete", "invoice") {
		t.Fatal("mutating the input changed the policy")
	}
}

func TestComposition(t *testing.T) {
	boom := errors.New("boom")
	allow := Func(func(context.Context, SubjectContext, Action, Resource) (*Decision, error) { return Allow("yes"), nil })
	deny := Func(func(context.Context, SubjectContext, Action, Resource) (*Decision, error) { return Deny("no"), nil })
	nilDecision := Func(func(context.Context, SubjectContext, Action, Resource) (*Decision, error) { return nil, nil })
	fail := Func(func(context.Context, SubjectContext, Action, Resource) (*Decision, error) { return nil, boom })
	owner := Func(func(_ context.Context, s SubjectContext, _ Action, r Resource) (*Decision, error) {
		if r.Attrs["owner_id"] == s.SubjectID {
			return Allow("owner"), nil
		}
		return Deny("not owner"), nil
	})

	tests := []struct {
		name    string
		engine  Engine
		allow   bool
		wantErr error
	}{
		{"DenyAll", DenyAll, false, nil},
		{"AnyOf empty", AnyOf(), false, nil},
		{"AnyOf deny,allow", AnyOf(deny, allow), true, nil},
		{"AnyOf deny,deny", AnyOf(deny, deny), false, nil},
		{"AnyOf nil decision is deny", AnyOf(nilDecision), false, nil},
		{"AnyOf error before allow fails closed", AnyOf(fail, allow), false, boom},
		{"AnyOf allow short-circuits error", AnyOf(allow, fail), true, nil},
		{"AllOf empty", AllOf(), false, nil},
		{"AllOf allow,allow", AllOf(allow, allow), true, nil},
		{"AllOf allow,deny", AllOf(allow, deny), false, nil},
		{"AllOf nil decision is deny", AllOf(allow, nilDecision), false, nil},
		{"AllOf error", AllOf(allow, fail), false, boom},
		{"RBAC or owner: owner", AnyOf(DenyAll, owner), true, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := tt.engine.Evaluate(ctx, SubjectContext{SubjectID: "u1"}, "write", Resource{Type: "book", Attrs: map[string]string{"owner_id": "u1"}})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if d.Allowed() != tt.allow {
				t.Fatalf("decision = %+v, want allow=%v", d, tt.allow)
			}
		})
	}
}
