#!/bin/sh
# Compatibility entry point: native component fault regression, not full Game Day.
# Run inside the dev image: VERSION build/NEW_OUTPUT are required.
set -eu
cd "$(dirname "$0")/../.."
exec tests/security/run-native-faults.sh "$@"
