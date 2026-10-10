module github.com/kararnab/iam/paseto/v2

go 1.26.0

require (
	aidanwoods.dev/go-paseto v1.6.0
	github.com/kararnab/iam/v2 v2.3.0
)

require (
	aidanwoods.dev/go-result v0.3.1 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// The in-repo core is used for development and CI. Go ignores replace
// directives in dependencies, so consumers get the tagged core module.
replace github.com/kararnab/iam/v2 => ../
