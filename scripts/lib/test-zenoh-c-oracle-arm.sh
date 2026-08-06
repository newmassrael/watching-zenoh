#!/usr/bin/env bash
# Drive `zenoh-c-oracle-arm.sh` on ALL FOUR feature combinations plus the
# no-config case, against synthesised prefixes.
#
# The point is that it drives the SHIPPING implementation. The first cut of the
# R311y566 fix was "verified" by running an inlined copy of its own logic in a
# shell one-liner, which establishes nothing about the file that runs in CI —
# the same class as a count guard nothing ties to its binary.
#
# Five cases, and the fifth is the load-bearing one: a prefix with no
# `zenoh_configure.h` must FAIL rather than fall back to a default, because a
# silent default is exactly what made `capi-c-arms` unpassable on hosted.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARM="$HERE/zenoh-c-oracle-arm.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail=0

expect() {
    local name="$1" want="$2"; shift 2
    local dir="$WORK/$name/include"
    mkdir -p "$dir"
    : > "$dir/zenoh_configure.h"
    # Every case starts from the transport defines a real configure header
    # carries, so a matcher that keyed off "the file is nearly empty" would not
    # pass here.
    printf '#define Z_FEATURE_TRANSPORT_TCP\n#define Z_FEATURE_AUTH_USRPWD\n' \
        >> "$dir/zenoh_configure.h"
    for feature in "$@"; do
        printf '#define %s\n' "$feature" >> "$dir/zenoh_configure.h"
    done
    local got
    got="$(bash "$ARM" "$WORK/$name")"
    if [[ "$got" != "$want" ]]; then
        echo "  FAIL $name: want '$want' got '$got'" >&2
        fail=1
    else
        echo "  ok   $name -> $got"
    fi
}

echo "[zenoh-c-oracle-arm] four feature combinations:"
expect plain          nounstable
expect unstable_only  unstable       Z_FEATURE_UNSTABLE_API
expect shm_only       nounstable-shm Z_FEATURE_SHARED_MEMORY
expect both           unstable-shm   Z_FEATURE_UNSTABLE_API Z_FEATURE_SHARED_MEMORY

# A feature named only inside a COMMENT must not count — the configure header is
# generated, but a hand-edited or vendored one is not guaranteed to be.
mkdir -p "$WORK/commented/include"
printf '/* Z_FEATURE_UNSTABLE_API is off in this build */\n#define Z_FEATURE_TRANSPORT_TCP\n' \
    > "$WORK/commented/include/zenoh_configure.h"
got="$(bash "$ARM" "$WORK/commented")"
if [[ "$got" != "nounstable" ]]; then
    echo "  FAIL commented: a mention inside a comment counted as a define ($got)" >&2
    fail=1
else
    echo "  ok   commented -> $got"
fi

# THE LOAD-BEARING CASE: no configure header must be a REFUSAL, not a default.
mkdir -p "$WORK/noconfig/include"
if bash "$ARM" "$WORK/noconfig" >/dev/null 2>&1; then
    echo "  FAIL noconfig: a prefix with no zenoh_configure.h answered instead of" >&2
    echo "       refusing; a guessed arm is the defect this replaced" >&2
    fail=1
else
    echo "  ok   noconfig -> refused"
fi

if [[ $fail -ne 0 ]]; then
    echo "[zenoh-c-oracle-arm] FAIL" >&2
    exit 1
fi
echo "[zenoh-c-oracle-arm] all cases pass"
