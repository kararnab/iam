module github.com/kararnab/iam/oidc/v2

go 1.26.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/kararnab/iam/v2 v2.0.0
)

require golang.org/x/oauth2 v0.37.0 // indirect

// The in-repo core is used for development and CI. Go ignores replace
// directives in dependencies, so consumers get the tagged core module.
replace github.com/kararnab/iam/v2 => ../
