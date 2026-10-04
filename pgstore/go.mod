module github.com/kararnab/iam/pgstore/v2

go 1.26.0

require (
	github.com/jackc/pgx/v5 v5.11.0
	github.com/kararnab/iam/v2 v2.2.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// The in-repo core is used for development and CI. Go ignores replace
// directives in dependencies, so consumers get the tagged core module.
replace github.com/kararnab/iam/v2 => ../
