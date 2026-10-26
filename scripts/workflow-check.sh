#!/bin/sh
# Checks GitHub workflow files, the dist config and the toolchain file
# against the release rules:
#
#   - every action is pinned to a full commit, with its tag in a comment, and
#     every docker:// action to a sha256 digest;
#   - every cargo command that resolves dependencies passes --locked;
#   - the workflow sets read-only permissions at the top, and only the job
#     named "host" (which publishes the release and compiles nothing) may
#     ask for a write permission, in any form (block, { flow } or write-all);
#   - the repository token appears only in a step's env inside "host", never
#     in a job-wide env, so build steps and build scripts never see it;
#   - HOMEBREW_TAP_TOKEN, a token for the Homebrew tap repository alone,
#     appears only in a step inside "publish-homebrew-formula", never in a
#     job-wide env (that job, like every job but "host", may only read this
#     repository); no other secret appears, and nothing hands over every
#     secret at once;
#   - every checkout sets persist-credentials: false, so no token stays in
#     the checkout for the steps after it;
#   - a release.yml runs scripts/release-binary-check.sh after `dist build`
#     in its build-local-artifacts job;
#   - a release.yml sets a top-level concurrency group on github.ref with
#     cancel-in-progress: true, so a tag that starts two runs ends with one;
#   - the dist config sets precise-builds = true in [dist];
#   - the toolchain file names an exact Rust version, and every workflow
#     toolchain input is that version or nightly.
#
# Usage: sh scripts/workflow-check.sh [--dist-config FILE] [--toolchain FILE] WORKFLOW...
# Defaults: dist-workspace.toml and rust-toolchain.toml.
# Prints one line per problem and exits 1 when there is any, 2 on bad usage
# or a missing file.
#
# The awk program sticks to POSIX awk (no gawk or BSD extensions, no regex
# interval braces, no octal escapes inside regexes) so mawk and busybox awk
# run it too.
set -eu

DIST_CONFIG=dist-workspace.toml
TOOLCHAIN=rust-toolchain.toml
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dist-config) [ "$#" -ge 2 ] || { echo "--dist-config needs a file." >&2; exit 2; }; DIST_CONFIG="$2"; shift 2 ;;
        --toolchain) [ "$#" -ge 2 ] || { echo "--toolchain needs a file." >&2; exit 2; }; TOOLCHAIN="$2"; shift 2 ;;
        --) shift; break ;;
        *) break ;;
    esac
done

if [ "$#" -eq 0 ]; then
    echo "Name at least one workflow file." >&2
    exit 2
fi

status=0
for file in "$DIST_CONFIG" "$TOOLCHAIN"; do
    if [ ! -f "$file" ]; then
        echo "$file: not found." >&2
        exit 2
    fi
done

# The dist config: precise-builds = true inside the [dist] table.
awk -v file="$DIST_CONFIG" '
    /^[ ]*\[/ { table = $0; gsub(/[ ]/, "", table); next }
    table == "[dist]" && /^[ ]*precise-builds[ ]*=[ ]*true[ ]*(#.*)?$/ { ok = 1 }
    END {
        if (!ok) { print file ": [dist] does not set precise-builds = true"; exit 1 }
    }
' "$DIST_CONFIG" || status=1

# The toolchain file: an exact version such as 1.98.1.
channel="$(sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$TOOLCHAIN" | head -n 1)"
if ! printf '%s\n' "$channel" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' >/dev/null; then
    echo "$TOOLCHAIN: channel must be an exact Rust version such as 1.98.1, not ${channel:-empty}"
    status=1
fi

for file in "$@"; do
    if [ ! -f "$file" ]; then
        echo "$file: not found." >&2
        status=2
        continue
    fi
    isrelease=0
    [ "$(basename "$file")" = release.yml ] && isrelease=1
    awk -v file="$file" -v channel="$channel" -v toolchain_file="$TOOLCHAIN" -v isrelease="$isrelease" '
    function indent(s) { match(s, /^ */); return RLENGTH }
    function problem(msg) { print file ":" NR ": " msg; bad = 1 }
    function unquote(s) {
        sub(/[ ]+#.*$/, "", s)
        gsub(/["]/, "", s)
        gsub(q, "", s)
        sub(/^[ ]+/, "", s)
        sub(/[ ]+$/, "", s)
        return s
    }
    BEGIN {
        bad = 0; injobs = 0; job = ""; toplevel = ""; top_read = 0
        inperm = 0; perm_ind = 0; built = 0; guarded = 0
        cgroup = 0; ccancel = 0
        q = sprintf("%c", 39)
        # A cargo command that resolves dependencies, after a start, space,
        # quote or shell separator.
        cargo_re = "(^|[ ;&|(\"" q "])cargo( \\+[^ ]+)? (build|test|clippy|install|run|check|doc|fetch|metadata|bench|tree)([ \"" q "]|$)"
    }
    {
        line = $0
        # Skip comment and blank lines; neither can run or grant anything.
        if (line ~ /^[ ]*#/ || line ~ /^[ ]*$/) next
        ind = indent(line)

        if (line ~ /^[^ ]/) {
            toplevel = line
            sub(/:.*/, "", toplevel)
            injobs = (toplevel == "jobs")
            job = ""
        } else if (injobs && line ~ /^  [A-Za-z0-9_-]+:/) {
            job = line
            sub(/^  /, "", job)
            sub(/:.*/, "", job)
        }

        # Permissions: a permissions: line itself (flow map or write-all) and
        # every line of a permissions block under it.
        if (inperm && ind <= perm_ind) inperm = 0
        permline = inperm
        if (line ~ /^[ -]*"?permissions"?:/) {
            permline = 1
            rest = line
            sub(/^[ -]*"?permissions"?:[ ]*/, "", rest)
            if (rest == "") { inperm = 1; perm_ind = ind }
        }
        if (permline) {
            if (toplevel == "permissions" && line ~ /contents"?[ ]*:[ ]*"?read/) top_read = 1
            if (line ~ /write/) {
                if (!injobs) {
                    problem("the workflow-wide permissions grant write; grant it in the host job only")
                } else if (job != "host") {
                    problem("job " job " asks for a write permission; only host may")
                }
            }
        }

        # The repository token: only in a step env (indent 10 or more) in host.
        if (line ~ /secrets\.GITHUB_TOKEN|github\.token/) {
            if (!(injobs && job == "host" && ind >= 10)) {
                where = (job == "") ? "outside a job" : "in job " job
                problem("the repository token is set " where "; give it only to the step in host that needs it")
            }
        }

        # The Homebrew tap token: only in a step in publish-homebrew-formula.
        if (line ~ /secrets\.HOMEBREW_TAP_TOKEN/) {
            if (!(injobs && job == "publish-homebrew-formula" && ind >= 10)) {
                where = (job == "") ? "outside a job" : "in job " job
                problem("the Homebrew tap token is set " where "; give it only to the step in publish-homebrew-formula that pushes the formula")
            }
        }

        # No other secret, and never all of them at once.
        rest = line
        while (match(rest, /secrets\.[A-Za-z0-9_-]+/)) {
            name = substr(rest, RSTART + 8, RLENGTH - 8)
            if (name != "GITHUB_TOKEN" && name != "HOMEBREW_TAP_TOKEN") {
                problem("the secret " name " is not allowed; only GITHUB_TOKEN in host and HOMEBREW_TAP_TOKEN in publish-homebrew-formula are")
            }
            rest = substr(rest, RSTART + RLENGTH)
        }
        if (line ~ /secrets\[|[(][ ]*secrets[ ]*[)]|secrets:[ ]*inherit/) {
            problem("the workflow hands over every secret; name the one a step needs")
        }

        # A checkout must not leave its token behind.
        if (line ~ /^[ -]*persist-credentials:[ ]*["]?true/) {
            problem("a checkout keeps its token for the steps after it; set persist-credentials: false")
        }

        # Actions pinned by full commit with the tag in a comment; docker
        # actions by digest.
        if (line ~ /^[ -]*uses:[ ]/) {
            ref = line
            sub(/^[ -]*uses:[ ]*/, "", ref)
            comment = ""
            if (index(ref, "#") > 0) {
                comment = substr(ref, index(ref, "#") + 1)
                ref = substr(ref, 1, index(ref, "#") - 1)
            }
            gsub(/["]/, "", ref)
            gsub(q, "", ref)
            gsub(/ /, "", ref)
            if (ref ~ /^docker:\/\//) {
                digest = ref
                if (sub(/^.*@sha256:/, "", digest) != 1 || length(digest) != 64 || digest !~ /^[0-9a-f]+$/) {
                    problem(ref " is not pinned to a sha256 digest")
                }
            } else if (ref !~ /^\.\//) {
                sha = ref
                sub(/^[^@]*@/, "", sha)
                if (index(ref, "@") == 0 || length(sha) != 40 || sha !~ /^[0-9a-f]+$/) {
                    problem(ref " is not pinned to a full commit")
                } else if (comment !~ /[^ ]/) {
                    problem(ref " needs its tag in a comment after the commit")
                }
            }
        }

        # Every cargo command on the line passes --locked: split the line at
        # shell separators and check each command on its own.
        segs = line
        gsub(/&&|\|\||;|\|/, "\n", segs)
        n = split(segs, part, "\n")
        for (i = 1; i <= n; i++) {
            if (match(part[i], cargo_re) && part[i] !~ /--locked/) {
                cmd = substr(part[i], RSTART)
                sub(/^[^c]*/, "", cmd)
                cmd = unquote(cmd)
                if (split(cmd, word, " ") >= 3 && word[2] ~ /^\+/) cmd = word[1] " " word[2] " " word[3]
                else cmd = word[1] " " word[2]
                problem("a cargo command without --locked: " cmd)
            }
        }

        # Toolchain inputs: the version rust-toolchain.toml names, or nightly.
        if (line ~ /^[ ]*toolchain:/) {
            want = line
            sub(/^[ ]*toolchain:/, "", want)
            want = unquote(want)
            if (want != "nightly" && want != channel) {
                problem("toolchain " want " is not " channel ", which " toolchain_file " names")
            }
        }

        # release.yml: one run per tag. A top-level concurrency block keyed
        # on github.ref that cancels the run already in progress.
        if (isrelease && toplevel == "concurrency") {
            if (line ~ /^[ ]+group:/ && line ~ /github\.ref/) cgroup = 1
            if (line ~ /^[ ]+cancel-in-progress:[ ]*true[ ]*$/) ccancel = 1
        }

        # release.yml: the binary check runs after dist build in the job
        # that builds the binaries.
        if (isrelease && job == "build-local-artifacts") {
            if (line ~ /dist build/) built = 1
            if (built && line ~ /scripts\/release-binary-check\.sh/) guarded = 1
        }
    }
    END {
        if (!top_read) { print file ": the workflow does not set contents: read at the top"; bad = 1 }
        if (isrelease && !(cgroup && ccancel)) {
            print file ": the workflow does not run one release per tag (concurrency group on github.ref with cancel-in-progress: true)"
            bad = 1
        }
        if (isrelease && !guarded) {
            print file ": job build-local-artifacts does not run scripts/release-binary-check.sh after dist build"
            bad = 1
        }
        exit bad
    }
    ' "$file" || status=1
done

if [ "$status" -eq 0 ]; then
    echo "Workflows follow the release rules."
fi
exit "$status"
