#!/bin/sh
set -eu
# Tool dependencies stay outside the application module graph.
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"
exec go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
