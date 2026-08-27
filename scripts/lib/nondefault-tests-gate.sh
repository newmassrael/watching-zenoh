#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2153 (no register item) — RUN the tests a non-default feature is the only way
# to reach. `nondefault-features-gate.sh` beside this one COMPILES them; nothing
# ran them before a push.
#
# The citation reads `no register item` for the reason `debt_plane_census.py`
# gives for its own: the item this closes -- unregistered open-debt item 542 --
# lives in the agent-memory register, which has no store id for
# `gate_provenance_lint.py` to resolve. The item is named in prose below.
#
# ## The defect, measured before this existed
#
# R2150 and R2151 each built an instrument in two halves, deliberately sharing no
# predicate: a PYTHON half that reads the tree (`unhonoured_kind_evidence_gate.py`,
# pre-push gate 2g) and a RUST half that owns the list shape
# (`#[test]`s in `wz-runtime-tokio`'s `zenoh_config`). Only the python half had a
# local gate.
#
#   * `zenoh_config` is `#[cfg(feature = "zenoh-config-emit")]`, and that feature
#     is NOT in the crate's `default` set;
#   * pre-push gate 3 is `cargo test -p <pkg>` at default features, so it does
#     not compile the module at all;
#   * pre-push gate 7 is `cargo check -p <pkg> --all-features`, so it compiles
#     the tests and never runs them -- which is this item's whole point;
#   * the only place they ran was hosted Layer C1bn.
#
# MEASURED: seven `#[test]` fns in that module assert on the same constants the
# python gate parses, and all four of the Rust-half red-first probes R2150 and
# R2151 ran died at exit 101 while passing pre-push. The asymmetry was reported
# to the owner as two options -- close it, or leave it to hosted CI -- and the
# owner's answer on 2026-08-27 was to close it: run that half before the push,
# with the measured cost accepted.
#
# ## Why a shared script and not a line in the hook
#
# The lane and the hook must not be able to disagree about WHAT to run. Layer
# C1bn used to carry the command inline; it now calls this file, so there is one
# spelling of the leg and one guard on its result. Adding a leg is one row in
# LEGS below and both callers get it.
#
# ## What it refuses
#
#   * an empty LEGS table -- a gate whose population is zero reports green about
#     nothing;
#   * a malformed row;
#   * a leg whose filter matched NO test. `cargo test` prints `ok` for a filter
#     that selects nothing, so "the leg passed" and "the leg ran" are different
#     facts and only the second one is worth anything.
#
# ## What it does NOT cover, by name
#
# One leg, in one crate. Gate 7 reports 20 workspace members carrying any
# non-default feature, so this table is a floor and is meant to grow: any other
# crate's feature-gated tests are still compiled-but-unrun locally. Extending it
# is per-leg work -- a leg has to be safe and quick to run on a developer's
# machine before it belongs here -- not a sweep.
#
# Usage:
#   bash scripts/lib/nondefault-tests-gate.sh            # every leg
#   bash scripts/lib/nondefault-tests-gate.sh --list     # name them, run nothing

set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# package|features|test-name-filter
#
# `zenoh_config::` is the module the two instruments live in; the filter is the
# module path so a test ADDED there is covered without touching this table.
LEGS=(
    "wz-runtime-tokio|zenoh-config-emit|zenoh_config::"
)

if [[ ${#LEGS[@]} -eq 0 ]]; then
    echo "nondefault-tests: FAIL -- the LEGS table is empty, so this gate would" >&2
    echo "  report success having run nothing. A population of zero is a failure," >&2
    echo "  not a clean tree." >&2
    exit 1
fi

if [[ "${1:-}" == "--list" ]]; then
    for leg in "${LEGS[@]}"; do
        IFS='|' read -r pkg feats filter <<<"$leg"
        echo "  $pkg --features $feats  $filter"
    done
    exit 0
fi

rc=0
for leg in "${LEGS[@]}"; do
    IFS='|' read -r pkg feats filter <<<"$leg"
    if [[ -z "$pkg" || -z "$feats" || -z "$filter" ]]; then
        echo "nondefault-tests: FAIL -- malformed leg row: '$leg'" >&2
        exit 1
    fi
    out="$(cd "$repo/crates" && cargo test -p "$pkg" --features "$feats" "$filter" --quiet 2>&1)"
    status=$?
    if [[ $status -ne 0 ]]; then
        echo "nondefault-tests: FAIL -- $pkg --features $feats $filter (exit $status)" >&2
        echo "$out" >&2
        rc=1
        continue
    fi
    # A filter that selects nothing still prints `ok`. Read the COUNT, which is
    # the only line that distinguishes "passed" from "ran".
    ran="$(grep -oE '^test result: ok\. [0-9]+ passed' <<<"$out" \
        | grep -oE '[0-9]+' | sort -rn | head -1)"
    if [[ -z "$ran" || "$ran" -lt 1 ]]; then
        echo "nondefault-tests: FAIL -- $pkg --features $feats $filter matched NO test." >&2
        echo "  The filter passed and ran nothing, which is the shape a renamed or" >&2
        echo "  moved module leaves behind. Re-point the leg in LEGS." >&2
        echo "$out" >&2
        rc=1
        continue
    fi
    echo "  nondefault-tests: $pkg --features $feats $filter -> $ran test(s)"
done

exit $rc
