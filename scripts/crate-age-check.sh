#!/bin/sh
# Lists registry crates in Cargo.lock released fewer than 30 days ago, and
# fails unless scripts/crate-age-allow.txt names each one with a reason.
# Target: about 8 minutes for the whole lock file (one crates.io request per second).
#
# Usage: sh scripts/crate-age-check.sh [--lock FILE] [--allow FILE] [--since OLD_LOCK] [--days N]
#   --since skips packages whose name and version are already in OLD_LOCK
#   (a quick local run), and then does not report allow entries that no
#   longer apply.
# Tests set CRATE_AGE_DATES=<file of "name version YYYY-MM-DD [yanked]" lines>
# instead of using the network, and CRATE_AGE_TODAY=YYYY-MM-DD for the date.
# Exit codes: 0 all clear, 1 a young crate is not allowed, 2 bad usage or
# allow line, 3 crates.io unreachable.
set -eu

LOCK=Cargo.lock
ALLOW=scripts/crate-age-allow.txt
SINCE=""
DAYS=30
UA="socketchat crate-age-check (https://github.com/sachio222/socketchat_v4)"

usage() {
    echo "Usage: sh scripts/crate-age-check.sh [--lock FILE] [--allow FILE] [--since OLD_LOCK] [--days N]" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    [ $# -ge 2 ] || usage
    case "$1" in
        --lock) LOCK="$2" ;;
        --allow) ALLOW="$2" ;;
        --since) SINCE="$2" ;;
        --days) DAYS="$2" ;;
        *) usage ;;
    esac
    shift 2
done
case "$DAYS" in
    '' | *[!0-9]*) usage ;;
esac
[ -r "$LOCK" ] || { echo "Can't read $LOCK." >&2; exit 2; }
[ -r "$ALLOW" ] || { echo "Can't read $ALLOW." >&2; exit 2; }
if [ -n "$SINCE" ] && [ ! -r "$SINCE" ]; then
    echo "Can't read $SINCE." >&2
    exit 2
fi

# Prints "name version" for each registry package in a lock file.
registry_packages() {
    awk '
        function flush() { if (name != "" && reg) print name, version }
        /^\[\[package\]\]/ { flush(); name = ""; version = ""; reg = 0; next }
        /^name = / { name = $3; gsub(/"/, "", name) }
        /^version = / { version = $3; gsub(/"/, "", version) }
        /^source = "registry\+/ { reg = 1 }
        END { flush() }
    ' "$1"
}

# Day count of a YYYY-MM-DD date, so differences are whole days.
DAYNUM='
    function dn(s,   y, m, d) {
        y = substr(s, 1, 4) + 0; m = substr(s, 6, 2) + 0; d = substr(s, 9, 2) + 0
        if (m <= 2) { y--; m += 12 }
        return 365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + d
    }
'

# Allow file: check every line, then print "name version reason" for each entry.
BAD=$(awk '
    { line = $0; sub(/#.*/, "", line) }
    split(line, f, " ") == 0 { next }
    split(line, f, " ") < 3 { printf "scripts/crate-age-allow.txt line %d names a crate but gives no reason.\n", NR }
' "$ALLOW")
if [ -n "$BAD" ]; then
    echo "$BAD" >&2
    exit 2
fi
ALLOWED=$(awk '
    { line = $0; sub(/#.*/, "", line) }
    NF == 0 { next }
    { split(line, f, " "); r = line; sub(/^[ \t]*[^ \t]+[ \t]+[^ \t]+[ \t]+/, "", r); sub(/[ \t]+$/, "", r); print f[1], f[2], r }
' "$ALLOW")

PKGS=$(registry_packages "$LOCK")
if [ -n "$SINCE" ]; then
    PKGS=$({
        registry_packages "$SINCE" | sed 's/^/O /'
        printf '%s\n' "$PKGS" | sed 's/^/N /'
    } | awk '
        $1 == "O" { seen[$2 " " $3] = 1; next }
        !(($2 " " $3) in seen) { print $2, $3 }
    ')
fi

if [ -n "${CRATE_AGE_TODAY:-}" ]; then
    TODAY="$CRATE_AGE_TODAY"
else
    TODAY=$(date -u +%Y-%m-%d)
fi

# fetch URL: prints the body after a one-second pause (the crates.io data
# access policy asks for at most one request per second); on failure prints
# curl's message and returns 3.
fetch() {
    sleep 1
    if ! BODY=$(curl -sS --fail --retry 3 --max-time 30 -A "$UA" "$1" 2>&1); then
        echo "Couldn't reach crates.io to read release dates: $BODY." >&2
        return 3
    fi
    printf '%s\n' "$BODY"
}

# date_of NAME VERSION: prints the release date.
date_of() {
    if [ -n "${CRATE_AGE_DATES:-}" ]; then
        awk -v n="$1" -v v="$2" '$1 == n && $2 == v { print $3; exit }' "$CRATE_AGE_DATES"
    else
        json=$(fetch "https://crates.io/api/v1/crates/$1/$(printf '%s' "$2" | sed 's/+/%2B/g')") || exit 3
        printf '%s\n' "$json" |
            awk 'match($0, /"created_at" *: *"[0-9-]+/) { s = substr($0, RSTART, RLENGTH); sub(/.*"/, "", s); print s; exit }'
    fi
}

# versions_of NAME: prints "version date [yanked]" for every release.
versions_of() {
    if [ -n "${CRATE_AGE_DATES:-}" ]; then
        awk -v n="$1" '$1 == n { $1 = ""; sub(/^ /, ""); print }' "$CRATE_AGE_DATES"
    else
        json=$(fetch "https://crates.io/api/v1/crates/$1/versions?per_page=100") || exit 3
        printf '%s\n' "$json" |
            awk '
                {
                    gsub(/"num" *: *"/, "\n")
                    n = split($0, rec, "\n")
                    for (i = 2; i <= n; i++) {
                        r = rec[i]; v = r; sub(/".*/, "", v)
                        d = ""
                        if (match(r, /"created_at" *: *"[0-9-]+/)) { d = substr(r, RSTART, RLENGTH); sub(/.*"/, "", d) }
                        y = (r ~ /"yanked" *: *true/) ? " yanked" : ""
                        if (d != "") print v, d y
                    }
                }
            '
    fi
}

# older_than NAME VERSION: prints the newest release in range that is old enough.
older_than() {
    list=$(versions_of "$1") || exit 3
    printf '%s\n' "$list" | awk -v v="$2" -v today="$TODAY" -v days="$DAYS" "$DAYNUM"'
        function key(s,   p) { sub(/\+.*/, "", s); split(s, p, "."); return p[1] * 1e12 + p[2] * 1e6 + p[3] }
        function part(s, i,   p) { sub(/\+.*/, "", s); split(s, p, "."); return p[i] + 0 }
        BEGIN { want = part(v, 1) " " part(v, 2) " " part(v, 3) }
        {
            ver = $1; base = ver; sub(/\+.*/, "", base)
            if (base ~ /-/ || $3 == "yanked") next
            if (dn(today) - dn($2) < days) next
            if (part(ver, 1) != part(v, 1)) next
            if (part(v, 1) == 0 && part(ver, 2) != part(v, 2)) next
            if (part(v, 1) == 0 && part(v, 2) == 0 && part(ver, 3) != part(v, 3)) next
            if (best == "" || key(ver) > bestkey) { best = ver; bestkey = key(ver) }
        }
        END { if (best != "") print best }
    '
}

STATUS=0
YOUNG=""
while read -r name version; do
    [ -n "$name" ] || continue
    released=$(date_of "$name" "$version")
    if [ -z "$released" ]; then
        echo "No release date found for $name $version." >&2
        exit 3
    fi
    age=$(awk -v t="$TODAY" -v r="$released" "$DAYNUM"'BEGIN { print dn(t) - dn(r) }')
    [ "$age" -lt "$DAYS" ] || continue
    YOUNG="$YOUNG$name $version
"
    reason=$(printf '%s\n' "$ALLOWED" | awk -v n="$name" -v v="$version" '
        $1 == n && $2 == v { r = $0; sub(/^[^ ]+ [^ ]+ /, "", r); print r; exit }')
    if [ -n "$reason" ]; then
        echo "$name $version is $age days old and allowed: $reason"
        continue
    fi
    STATUS=1
    older=$(older_than "$name" "$version")
    if [ -n "$older" ]; then
        echo "$name $version was released on $released, $age days ago. Newest release at least $DAYS days old: $older. Hold it back with: cargo update -p $name@$version --precise $older"
    else
        echo "$name $version was released on $released, $age days ago, and no release in its range is $DAYS days old yet. If the tree needs it, add it to scripts/crate-age-allow.txt with the reason."
    fi
done <<EOF
$PKGS
EOF

if [ -z "$SINCE" ]; then
    printf '%s\n' "$ALLOWED" | while read -r name version _; do
        [ -n "$name" ] || continue
        case "
$YOUNG" in
            *"
$name $version
"*) ;;
            *) echo "scripts/crate-age-allow.txt: $name $version no longer needs an entry; remove it." ;;
        esac
    done
fi

if [ "$STATUS" -eq 0 ]; then
    echo "Every registry crate in $LOCK is at least $DAYS days old, or allowed."
fi
exit "$STATUS"
