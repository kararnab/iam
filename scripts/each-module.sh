#!/bin/sh
# Runs the given command in every Go module of the repository.
# Usage: scripts/each-module.sh go test ./...
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
status=0
for mod in $(find "$root" -name go.mod -not -path '*/.git/*' | sort); do
	dir=$(dirname "$mod")
	if [ "$dir" = "$root" ]; then echo "==> ."; else echo "==> ${dir#"$root"/}"; fi
	(cd "$dir" && "$@") || status=1
done
exit $status
