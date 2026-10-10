module github.com/kararnab/iam/redisstore/v2

go 1.26.0

require (
	github.com/kararnab/iam/v2 v2.3.0
	github.com/redis/go-redis/v9 v9.22.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
)

// The in-repo core is used for development and CI. Go ignores replace
// directives in dependencies, so consumers get the tagged core module.
replace github.com/kararnab/iam/v2 => ../
