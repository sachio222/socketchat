#!/bin/sh
# Tests scripts/crate-age-check.sh against the fixtures in
# scripts/crate-age-fixtures, with no network. Prints ok when every case passes.
set -eu

cd "$(dirname "$0")/.."
F=scripts/crate-age-fixtures
CHECK=scripts/crate-age-check.sh
export CRATE_AGE_TODAY=2026-10-20
export CRATE_AGE_DATES="$F/dates.txt"
OUT="$(mktemp)"
BIN="$(mktemp -d)"
trap 'rm -f "$OUT"; rm -r "$BIN"' EXIT

fail() {
    echo "FAIL: $1" >&2
    if [ -s "$OUT" ]; then cat "$OUT" >&2; fi
    exit 1
}
# run CASE EXPECTED_STATUS args...
run() {
    case_name="$1"
    want="$2"
    shift 2
    got=0
    sh "$CHECK" "$@" >"$OUT" 2>&1 || got=$?
    [ "$got" -eq "$want" ] || fail "$case_name: exit $got, wanted $want"
}
has() { grep -F -- "$2" "$OUT" >/dev/null || fail "$1: output lacks: $2"; }
lacks() { if grep -F -- "$2" "$OUT" >/dev/null; then fail "$1: output names: $2"; fi; }

run young_crate_fails 1 --lock "$F/young.lock" --allow /dev/null
has young_crate_fails "aaa 1.2.0 was released on 2026-10-10, 10 days ago."
has young_crate_fails "--precise 1.1.4"
lacks young_crate_fails bbb
lacks young_crate_fails local-crate
lacks young_crate_fails gitdep

run allowed_crate_passes 0 --lock "$F/young.lock" --allow "$F/allow-ok.txt"
has allowed_crate_passes "aaa 1.2.0 is 10 days old and allowed: required by ccc 0.9.1"

run allow_covers_one_version_only 1 --lock "$F/young.lock" --allow "$F/allow-other-version.txt"

run allow_line_needs_a_reason 2 --lock "$F/young.lock" --allow "$F/allow-no-reason.txt"
has allow_line_needs_a_reason "scripts/crate-age-allow.txt line 1 names a crate but gives no reason."

run stale_allow_entry_is_named 0 --lock "$F/young.lock" --allow "$F/allow-stale.txt"
has stale_allow_entry_is_named "scripts/crate-age-allow.txt: bbb 0.3.1 no longer needs an entry; remove it."

run since_skips_unchanged_same 0 --lock "$F/young.lock" --allow /dev/null --since "$F/base-same.lock"
run since_skips_unchanged_older 1 --lock "$F/young.lock" --allow /dev/null --since "$F/base-older.lock"

for tool in sh sed awk sort; do ln -s "$(command -v "$tool")" "$BIN/$tool"; done
got=0
PATH="$BIN" sh "$CHECK" --lock "$F/young.lock" --allow "$F/allow-ok.txt" >"$OUT" 2>&1 || got=$?
[ "$got" -eq 0 ] || fail "no_network_in_tests: exit $got"

echo ok
