#!/bin/sh
# Fails when a release binary holds test-only code: socketchat-core compiles
# TEST_HOOKS_MARKER (crates/socketchat-core/src/lib.rs) into a program only
# when its test-hooks feature is on.
#
# Usage: sh scripts/release-binary-check.sh BINARY...
# Exits 1 when a binary holds test-only code, 2 when none is named, one is
# missing or one cannot be read, so a build that put its binary somewhere
# else cannot pass quietly.
set -eu

MARKER="socketchat-core test-hooks compiled in"

if [ "$#" -eq 0 ]; then
    echo "Name at least one binary to check; none was found." >&2
    exit 2
fi

status=0
for bin in "$@"; do
    if [ ! -f "$bin" ]; then
        echo "$bin: not found." >&2
        status=2
        continue
    fi
    found=0
    grep -a -q -F -- "$MARKER" "$bin" 2>/dev/null || found=$?
    case "$found" in
        0)
            echo "$bin holds test-only code (socketchat-core's test-hooks feature)." >&2
            [ "$status" -eq 2 ] || status=1
            ;;
        1)
            echo "$bin: no test-only code."
            ;;
        *)
            echo "$bin could not be read (grep exit $found)." >&2
            status=2
            ;;
    esac
done
exit "$status"
