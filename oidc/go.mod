module github.com/kararnab/iam/oidc

go 1.26.0

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/kararnab/iam v0.0.0
)

require golang.org/x/oauth2 v0.37.0 // indirect

replace github.com/kararnab/iam => ../
