#!/bin/sh
set -eu
exec python3 "$(dirname "$0")/test-e2e.py" "$@"
