# Policy

Authorization is decided by a `policy.Engine`. `iam.New` refuses to start
without one, so there is no allow-all default.

```go
type Engine interface {
    Evaluate(ctx context.Context, subject policy.SubjectContext, action policy.Action, resource policy.Resource) (*policy.Decision, error)
}
```

`Service.Authorize` and `httpauth.RequirePermission` call the engine. A
missing subject, a nil decision, anything other than `EffectAllow`, or an
engine error all mean **deny**. Every denial is audited (`policy_denied`)
and counted.

## RBAC

```go
rbac, err := policy.NewRBAC(map[string][]policy.Permission{
    "admin":  {policy.P(policy.Wildcard, policy.Wildcard)},
    "editor": {policy.P("read", "book"), policy.P("write", "book")},
    "reader": {policy.P("read", "book")},
})
```

- Roles come from your `iam.SubjectLoader` (`Subject.Roles`).
- `Wildcard` (`*`) matches any action or resource type. Use it sparingly.
- Empty actions or resource types are always denied.
- `rbac.Grants(role, action, type)` helps UIs decide what to show, but
  authorization must still go through `Evaluate`.

## Ownership and attributes: composing engines

RBAC looks at roles and resource types only. Put rules about specific
resources in a `policy.Func`, and combine:

```go
ownsBook := policy.Func(func(ctx context.Context, s policy.SubjectContext, a policy.Action, r policy.Resource) (*policy.Decision, error) {
    if r.Type == "book" && r.Attrs["owner_id"] == s.SubjectID {
        return policy.Allow("owner"), nil
    }
    return policy.Deny("not owner"), nil
})

engine := policy.AnyOf(rbac, ownsBook)       // editors, or the owner
// policy.AllOf(rbac, sameTenant)            // role AND tenant check
```

`AnyOf` allows if any engine allows. `AllOf` allows only if all of them do.
Both fail closed: an error stops evaluation with a deny.

With `httpauth`, fill in the resource from the request:

```go
auth.RequirePermission("write", "book", func(r *http.Request) policy.Resource {
    book := loadBook(r.PathValue("id"))
    return policy.Resource{ID: book.ID, Attrs: map[string]string{"owner_id": book.OwnerID}}
})(handler)
```

## Custom engines

Implement `Engine` to call OPA, Cedar, a ReBAC service, or a database.
Return an error rather than an allow when you cannot decide. Keep reasons
short and free of personal data: they end up in audit logs.
