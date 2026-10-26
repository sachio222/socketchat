#!/bin/sh
# Tests scripts/workflow-check.sh against the fixtures in
# scripts/workflow-fixtures. Prints ok when every case passes.
set -eu

cd "$(dirname "$0")/.."
F=scripts/workflow-fixtures
CHECK=scripts/workflow-check.sh
OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

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
# Same, with the fixture dist config and toolchain file that pass.
runf() {
    case_name="$1"
    want="$2"
    shift 2
    run "$case_name" "$want" --dist-config "$F/dist-precise.toml" --toolchain "$F/toolchain-pinned.toml" "$@"
}
has() { grep -F -- "$2" "$OUT" >/dev/null || fail "$1: output lacks: $2"; }
count() {
    n="$(grep -c -F -- "$2" "$OUT" || true)"
    [ "$n" -eq "$3" ] || fail "$1: '$2' appears $n times, wanted $3"
}

runf good_workflow_passes 0 "$F/good.yml"
has good_workflow_passes "Workflows follow the release rules."

runf bad_workflow_fails 1 "$F/bad.yml"
B="$F/bad.yml"
has bad_workflow_fails "$B:3: the workflow-wide permissions grant write"
has bad_workflow_fails "$B:12: the repository token is set in job plan"
has bad_workflow_fails "$B:14: actions/checkout@v6 is not pinned to a full commit"
has bad_workflow_fails "$B:15: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a needs its tag in a comment"
has bad_workflow_fails "$B:16: dtolnay/rust-toolchain@stable is not pinned to a full commit"
has bad_workflow_fails "$B:21: job build asks for a write permission; only host may"
has bad_workflow_fails "$B:23: a cargo command without --locked: cargo build"
has bad_workflow_fails "$B:25: a cargo command without --locked: cargo +nightly install"
has bad_workflow_fails "$B:28: the repository token is set in job build"
# A job-wide env in host still reaches every step, so it is refused too.
has bad_workflow_fails "$B:34: the repository token is set in job host"
has bad_workflow_fails "$B: the workflow does not set contents: read at the top"
count bad_workflow_fails "$B:" 11

runf no_top_permissions_fails 1 "$F/no-top-permissions.yml"
has no_top_permissions_fails "does not set contents: read at the top"

# write-all and flow-style maps are write permissions too; host may have them.
P="$F/permissions.yml"
runf permission_forms_fail 1 "$P"
has permission_forms_fail "$P:10: job plan asks for a write permission"
has permission_forms_fail "$P:16: job build asks for a write permission"
has permission_forms_fail "$P:24: job test asks for a write permission"
count permission_forms_fail "$P:" 3

# The Homebrew tap token only in a step of publish-homebrew-formula, which
# may not write to this repository; no other secret anywhere.
S="$F/secrets.yml"
runf secrets_fail 1 "$S"
has secrets_fail "$S:14: the Homebrew tap token is set in job build; give it only to the step in publish-homebrew-formula that pushes the formula"
has secrets_fail "$S:20: job publish-homebrew-formula asks for a write permission; only host may"
has secrets_fail "$S:22: the Homebrew tap token is set in job publish-homebrew-formula; give it only to the step in publish-homebrew-formula that pushes the formula"
has secrets_fail "$S:27: the secret NPM_TOKEN is not allowed; only GITHUB_TOKEN in host and HOMEBREW_TAP_TOKEN in publish-homebrew-formula are"
has secrets_fail "$S:31: the workflow hands over every secret; name the one a step needs"
has secrets_fail "$S:40: the Homebrew tap token is set in job host; give it only to the step in publish-homebrew-formula that pushes the formula"
has secrets_fail "$S:44: a checkout keeps its token for the steps after it; set persist-credentials: false"
count secrets_fail "$S:" 7

W="$F/write-all-top.yml"
runf write_all_at_top_fails 1 "$W"
has write_all_at_top_fails "$W:2: the workflow-wide permissions grant write"
has write_all_at_top_fails "$W: the workflow does not set contents: read at the top"

# Quoted commands and each command of a chain are checked on their own.
C="$F/cargo-lines.yml"
runf cargo_lines_fail 1 "$C"
has cargo_lines_fail "$C:12: a cargo command without --locked: cargo build"
has cargo_lines_fail "$C:13: a cargo command without --locked: cargo test"
has cargo_lines_fail "$C:14: a cargo command without --locked: cargo test"
has cargo_lines_fail "$C:15: a cargo command without --locked: cargo build"
has cargo_lines_fail "$C:20: a cargo command without --locked: cargo doc"
count cargo_lines_fail "$C:" 5

D="$F/docker.yml"
runf docker_needs_a_digest 1 "$D"
has docker_needs_a_digest "$D:12: docker://alpine:3.20 is not pinned to a sha256 digest"
has docker_needs_a_digest "$D:13: docker://alpine@sha256:abc123 is not pinned to a sha256 digest"
count docker_needs_a_digest "$D:" 2

# Workflows install the Rust version rust-toolchain.toml names, or nightly.
T="$F/toolchain.yml"
runf toolchain_matches_file 1 "$T"
has toolchain_matches_file "$T:14: toolchain stable is not 1.98.1, which $F/toolchain-pinned.toml names"
has toolchain_matches_file "$T:17: toolchain 1.97.0 is not 1.98.1, which $F/toolchain-pinned.toml names"
count toolchain_matches_file "$T:" 2

run toolchain_file_needs_a_version 1 --dist-config "$F/dist-precise.toml" --toolchain "$F/toolchain-stable.toml" "$F/good.yml"
has toolchain_file_needs_a_version "$F/toolchain-stable.toml: channel must be an exact Rust version such as 1.98.1, not stable"

# Release builds must build the socketchat package alone.
run dist_needs_precise_builds 1 --dist-config "$F/dist-imprecise.toml" --toolchain "$F/toolchain-pinned.toml" "$F/good.yml"
has dist_needs_precise_builds "$F/dist-imprecise.toml: [dist] does not set precise-builds = true"

run missing_dist_config_is_named 2 --dist-config "$F/none.toml" --toolchain "$F/toolchain-pinned.toml" "$F/good.yml"
has missing_dist_config_is_named "$F/none.toml: not found."

# release.yml must check the built binaries after dist build, in the job
# that builds them.
runf release_guard_passes 0 "$F/release-guarded/release.yml"
runf release_without_guard_fails 1 "$F/release-unguarded/release.yml"
has release_without_guard_fails "$F/release-unguarded/release.yml: job build-local-artifacts does not run scripts/release-binary-check.sh after dist build"
runf release_guard_before_build_fails 1 "$F/release-guard-too-early/release.yml"
has release_guard_before_build_fails "$F/release-guard-too-early/release.yml: job build-local-artifacts does not run scripts/release-binary-check.sh after dist build"
runf release_without_concurrency_fails 1 "$F/release-two-runs/release.yml"
has release_without_concurrency_fails "$F/release-two-runs/release.yml: the workflow does not run one release per tag (concurrency group on github.ref with cancel-in-progress: true)"
runf release_keeping_old_run_fails 1 "$F/release-keeps-old-run/release.yml"
has release_keeping_old_run_fails "$F/release-keeps-old-run/release.yml: the workflow does not run one release per tag (concurrency group on github.ref with cancel-in-progress: true)"

run missing_file_is_named 2 "$F/missing.yml"
has missing_file_is_named "$F/missing.yml: not found."

run needs_a_file 2

# The real workflows, dist config and toolchain file must pass.
run repo_workflows_pass 0 .github/workflows/*.yml

echo ok
