#!/bin/sh
# Tests scripts/release-binary-check.sh on made-up binaries. Prints ok when
# every case passes.
set -eu

cd "$(dirname "$0")/.."
CHECK=scripts/release-binary-check.sh
MARKER="socketchat-core test-hooks compiled in"
DIR="$(mktemp -d)"
OUT="$DIR/out"
trap 'chmod 600 "$DIR/unreadable" 2>/dev/null || true; rm -r "$DIR"' EXIT

fail() {
    echo "FAIL: $1" >&2
    if [ -s "$OUT" ]; then cat "$OUT" >&2; fi
    exit 1
}
run() {
    case_name="$1"
    want="$2"
    shift 2
    got=0
    sh "$CHECK" "$@" >"$OUT" 2>&1 || got=$?
    [ "$got" -eq "$want" ] || fail "$case_name: exit $got, wanted $want"
}
has() { grep -F -- "$2" "$OUT" >/dev/null || fail "$1: output lacks: $2"; }

# Binary-looking files: text between NUL bytes, as in a real executable.
# A clean program may say "for a test" in its own words; only the marker
# that socketchat-core compiles in with test-hooks counts.
printf '\177ELF\000\000the server would not take the message for a test\000ok\000' >"$DIR/clean"
printf '\177ELF\000\000%s\000ok\000' "$MARKER" >"$DIR/hooked"

run clean_binary_passes 0 "$DIR/clean"
has clean_binary_passes "$DIR/clean: no test-only code."

run hooked_binary_fails 1 "$DIR/clean" "$DIR/hooked"
has hooked_binary_fails "$DIR/hooked holds test-only code"

run missing_binary_fails 2 "$DIR/hooked" "$DIR/missing"
has missing_binary_fails "$DIR/missing: not found."

run no_binary_fails 2
has no_binary_fails "none was found"

# A binary grep cannot read is a failure, never a pass.
cp "$DIR/clean" "$DIR/unreadable"
chmod 000 "$DIR/unreadable"
if [ -r "$DIR/unreadable" ]; then
    echo "skip unreadable_binary_fails: running as a user who can read anything"
else
    run unreadable_binary_fails 2 "$DIR/unreadable"
    has unreadable_binary_fails "$DIR/unreadable could not be read"
fi

# The marker here must match the one socketchat-core compiles in.
grep -F "pub const TEST_HOOKS_MARKER: &str = \"$MARKER\";" crates/socketchat-core/src/lib.rs >/dev/null ||
    fail "marker_matches_core: crates/socketchat-core/src/lib.rs does not define the marker this test uses"
grep -F "MARKER=\"$MARKER\"" "$CHECK" >/dev/null ||
    fail "marker_matches_check: $CHECK does not look for the marker this test uses"

echo ok
