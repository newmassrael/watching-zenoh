#!/usr/bin/env bash
# R311y566 (no register item) — print which zenoh-c ABI ARM the installed
# oracle at $1 (a prefix) is.
#
# zenoh-c's `Z_FEATURE_UNSTABLE_API` and `Z_FEATURE_SHARED_MEMORY` are
# INDEPENDENT axes and both move opaque type sizes, so "the installed zenoh-c"
# names one of FOUR builds. Everything that compares wz against that oracle has
# to know which, and the oracle says so itself: `zenoh_configure.h` is generated
# per build and carries a bare `#define` per enabled feature.
#
# R311y566 — this exists as its own file because it was previously a default
# rather than a reading. `check-capi-c-opaque-arms.sh` calibrated its generator
# against the `nounstable` table unconditionally; that matched the author's
# `~/.local`, which then held a plain `nounstable` install, and could NEVER
# match hosted CI's unstable+SHM oracle, so the `capi-c-arms` job redded on a
# check structurally unable to pass and the four-arm comparison behind it went
# unrun for rounds. R2278: that install was NOT upstream's published package,
# which is the `unstable-shm` build at every release measured.
#
# Split out rather than inlined so it can be DRIVEN on all four combinations by
# `scripts/lib/test-zenoh-c-oracle-arm.sh` — a probe against an inlined copy of
# the logic proves nothing about the logic that ships.
#
# Prints one of: nounstable | unstable | nounstable-shm | unstable-shm
# Exits 1 with a message on stderr when the prefix has no `zenoh_configure.h`,
# because a GUESSED arm is the defect this file exists to remove.
set -euo pipefail

prefix="${1:?usage: zenoh-c-oracle-arm.sh <prefix>}"
configure="$prefix/include/zenoh_configure.h"

if [[ ! -f "$configure" ]]; then
    echo "zenoh-c-oracle-arm: no $configure — the oracle's build cannot be" >&2
    echo "                    established, and guessing it is the bug this" >&2
    echo "                    replaced." >&2
    exit 1
fi

# A bare `#define NAME` with nothing after it. cbindgen emits exactly that shape;
# requiring the line start keeps a mention inside a comment from counting.
defined() {
    grep -qE "^[[:space:]]*#define[[:space:]]+$1([[:space:]]|\$)" "$configure"
}

unstable=0
shm=0
defined Z_FEATURE_UNSTABLE_API && unstable=1
defined Z_FEATURE_SHARED_MEMORY && shm=1

if [[ $unstable -eq 1 && $shm -eq 1 ]]; then
    echo "unstable-shm"
elif [[ $unstable -eq 1 ]]; then
    echo "unstable"
elif [[ $shm -eq 1 ]]; then
    echo "nounstable-shm"
else
    echo "nounstable"
fi
