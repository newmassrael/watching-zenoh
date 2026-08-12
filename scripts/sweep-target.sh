#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y733 (N25) — REAP THE BUILD ARTEFACTS THIS TREE NO LONGER USES.
#
# THE MEASUREMENT THAT MADE THIS EXIST. `crates/target` reached 24 GB (it is a
# symlink into ~/.buildcache here, which is its own trap -- see `size_kb`), and
# one full gate run takes it to 48 GB.
#
# A COUNT OF DUPLICATES IS NOT A MEASURE OF STALENESS, and the first version of
# this comment said it was. `debug/deps` held 710 executables under 277 names
# and that looked like 433 dead copies -- but after a full gate the duplicate
# count ROSE to 1404 of 1748 while the tree got SMALLER, because each copy is
# one feature combination some lane had just used. The duplicates measure how
# wide this workspace's matrix is. What is stale is what the gates DO NOT
# TOUCH, which is the only thing this removes: 10.5 GB, measured.
#
# WHY THE OBVIOUS TOOLS DO NOT REACH IT, each checked rather than assumed:
#
#   * `cargo -Z gc` is nightly-only and this workspace is pinned to stable
#     ("the `-Z` flag is only accepted on the nightly channel").
#   * `cargo sweep --time 1` and `--installed` both reported "would clean:
#     nothing". They key on AGE, and the duplicates are not old -- 689 of the
#     710 were built on ONE day, several within the same minute. They multiply
#     because every feature combination this workspace gates on (`C1bt`'s
#     `--no-default-features`, the per-crate lanes, the mutation sweep's
#     recompiles) produces its own hash.
#   * `--maxsize` works but is blunt: capping at 4 GB proposed deleting
#     20.4 GiB, because it evicts by age until the cap is met.
#   * `[profile.dev] incremental = false` (already set globally) bounds
#     `debug/incremental` only -- 244 MB -- and says nothing about `deps/`.
#
# WHAT ACTUALLY ANSWERS IT is a stamp: mark the time, run the gates, and reap
# what the gates did not touch. The criterion is "this build did not use it"
# rather than age or size, which is the only one that stays right as the
# feature matrix grows.
#
# THE HAZARD, AND WHY THIS REFUSES RATHER THAN DOCUMENTS IT. Reaping after a
# PARTIAL build deletes everything the partial build did not touch -- which is
# most of the tree. A comment saying "only run this after a full gate" is an
# obligation written as prose, and this workspace has measured what happens to
# those. So the reap MEASURES what it is about to remove and refuses when the
# share crosses a threshold, which is exactly the shape a partial build takes.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="$ROOT/crates/target"
# cargo-sweep takes the PROJECT path (the directory holding Cargo.toml), not
# the target path, and names the stamp itself. PROBED twice, because both
# halves were wrong in silence: a guessed filename made `stamp` report success
# while `reap` answered "no stamp", and passing `target/` made cargo-sweep fail
# with "manifest path crates/target/Cargo.toml does not exist" -- which
# `pipefail` turned into an exit 1 with no output at all.
PROJECT="$ROOT/crates"
STAMP="$PROJECT/sweep.timestamp"

# Above this share of the tree, a reap is far more likely to be a partial build
# than a genuine accumulation, and it stops to be told which.
MAX_SHARE=60

usage() {
    cat >&2 <<'USAGE'
usage: sweep-target.sh <stamp|reap|report> [--apply]

  stamp   mark the moment before a FULL gate run
  reap    remove artefacts untouched since the stamp (dry-run unless --apply)
  report  what is in target/ right now, and how much of it is duplicate

`reap` refuses when it would remove more than 60% of the tree: that is the
shape of a reap after a PARTIAL build, and it needs a human rather than a
default.
USAGE
    exit 2
}

need_sweep() {
    if ! command -v cargo-sweep >/dev/null 2>&1; then
        echo "sweep-target: FAIL — cargo-sweep is not on PATH." >&2
        echo "  install: cargo install cargo-sweep" >&2
        exit 1
    fi
}

# `-L` because `crates/target` is a SYMLINK here (to ~/.buildcache/...), and
# without it `du` measures the link itself and answers 0. That is not a cosmetic
# bug: the refusal below divides by this number, so a zero made the guard pass
# every time -- a safety check that fails OPEN, found by the report printing
# "target: 0.0B" beside 8.4 GB of executables.
size_kb() {
    local kb
    kb=$(du -skL "$1" 2>/dev/null | cut -f1)
    if [ -z "$kb" ] || [ "$kb" -le 0 ] 2>/dev/null; then
        echo "sweep-target: FAIL — cannot size $1, so the safety share below" >&2
        echo "  would be computed against zero and pass unconditionally." >&2
        exit 1
    fi
    echo "$kb"
}

human() { numfmt --to=iec --suffix=B --format='%.1f' $((${1:-0} * 1024)) 2>/dev/null || echo "${1:-0} KB"; }

case "${1:-}" in
stamp)
    need_sweep
    cargo sweep --stamp "$PROJECT" >/dev/null
    echo "sweep-target: stamped $STAMP"
    ;;

reap)
    need_sweep
    if [ ! -f "$STAMP" ]; then
        echo "sweep-target: FAIL — no stamp at $STAMP." >&2
        echo "  A reap without a stamp has nothing to compare against. Run" >&2
        echo "  'sweep-target.sh stamp' BEFORE the gate run, not after." >&2
        exit 1
    fi
    before=$(size_kb "$TARGET")
    # cargo-sweep prints the amount it would remove; ask it first, always.
    would=$(cargo sweep --dry-run --file "$PROJECT" 2>&1 | sed -n 's/.*Would clean: \(.*\) from.*/\1/p' | tail -1)
    echo "sweep-target: target is $(human "$before"), reap would remove ${would:-unknown}"

    # The refusal, measured rather than trusted: compare the tree before and
    # after a dry run is not possible, so the share is derived from what
    # cargo-sweep reports against the tree size.
    wkb=$(python3 - "$would" <<'PY'
import re, sys
s = (sys.argv[1] or "").strip()
m = re.match(r"([\d.]+)\s*([KMG]i?B)", s)
if not m:
    print(0)
else:
    v, u = float(m.group(1)), m.group(2)
    print(int(v * {"KiB": 1, "MiB": 1024, "GiB": 1024 * 1024, "KB": 1, "MB": 1024, "GB": 1024 * 1024}.get(u, 1)))
PY
)
    share=$(( before > 0 ? wkb * 100 / before : 0 ))
    echo "  that is ${share}% of the tree"
    if [ "$share" -gt "$MAX_SHARE" ]; then
        echo "sweep-target: REFUSING — ${share}% is over the ${MAX_SHARE}% limit." >&2
        echo "  A reap this large is the shape of a reap after a PARTIAL build:" >&2
        echo "  everything the partial build did not touch looks unused. Re-run" >&2
        echo "  the FULL gate, or delete the stamp and start again." >&2
        exit 1
    fi
    if [ "${2:-}" != "--apply" ]; then
        echo "  (dry run; pass --apply to remove)"
        exit 0
    fi
    cargo sweep --file "$PROJECT" >/dev/null
    after=$(size_kb "$TARGET")
    echo "sweep-target: $(human "$before") -> $(human "$after")"
    ;;

report)
    [ -e "$TARGET" ] || { echo "sweep-target: no $TARGET"; exit 0; }
    total=$(size_kb "$TARGET")
    echo "target: $(human "$total")"
    deps="$TARGET/debug/deps"
    if [ -d "$deps" ]; then
        bins=$(find "$deps" -maxdepth 1 -type f -executable ! -name '*.*' | wc -l)
        names=$(find "$deps" -maxdepth 1 -type f -executable ! -name '*.*' -printf '%f\n' |
            sed 's/-[0-9a-f]\{16\}$//' | sort -u | wc -l)
        kb=$(find "$deps" -maxdepth 1 -type f -executable ! -name '*.*' -printf '%s\n' |
            awk '{s+=$1} END {printf "%d", s/1024}')
        echo "debug/deps executables: $bins under $names names, $(human "$kb")"
        [ "$bins" -gt 0 ] && echo "  duplicates: $((bins - names)) ($(( (bins - names) * 100 / bins ))%)"
    fi
    [ -f "$STAMP" ] && echo "stamp: $(date -r "$STAMP" '+%F %T')" || echo "stamp: none"
    ;;

*) usage ;;
esac
