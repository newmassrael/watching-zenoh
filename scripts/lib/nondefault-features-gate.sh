#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2133 (no register item) — the NON-DEFAULT-FEATURE COMPILATION gate. The debt
# it closes is item 176 in the UNREGISTERED set, which has no store `debt-` id.
#
# ## The class, and why it needed a gate
#
# `reduced-features-gate.sh` next to this file asks whether a changed crate
# still builds with its defaults OFF. Nothing asked the opposite: whether the
# code behind a feature that is off BY DEFAULT gets compiled by anything local
# at all. It does not. pre-push gate 3 is `cargo test -p <pkg>` with default
# features, so a crate's non-default modules are not merely untested — they are
# never handed to rustc.
#
# The instance item 176 records: a probe reported green, the cause was not the
# code but the feature, and re-running with `--features dissect` died on the
# predicted line. R2133 reproduced it as a control PAIR on one tree, one host,
# 37 seconds apart, with a deliberate `E0308` inside `dissect.rs`:
#
#   cargo test -p wz-session-core --quiet                    -> exit 0
#   cargo test -p wz-session-core --features dissect --quiet -> exit 101
#
# pre-push reported a pass over code that does not compile. That is the whole
# defect, and it is why this gate compiles rather than lints.
#
# ## Why `check --all-features` and not clippy
#
# The sibling gate uses clippy because ITS class is lint-visible — an unused
# import, a test module whose every member is gated. This class is not: the
# failure is a hard compile error in code rustc never saw. `cargo check` is the
# cheapest thing that hands the code to the compiler, and `--all-targets` is
# required because a `cfg(test)` fixture behind a non-default feature is inside
# the same blind spot.
#
# ## What this deliberately does NOT do
#
# It does not sweep feature COMBINATIONS. `--all-features` is one build with
# every feature on, so a defect that appears only when feature A is on and B is
# off is invisible here — that axis is open-debt item 374 and has no instrument.
# What is closed is narrower and worth stating exactly: every line of a changed
# crate's non-default code is COMPILED by something local. Not "every
# combination of it is correct".
#
# ## Why the population is derived
#
# A crate with no non-default feature has nothing for this gate to add, and
# hand-listing the ones that do is a list that shuts its eyes on the next
# `[features]` block. The set comes from cargo's own metadata: a feature is
# non-default when it is outside the TRANSITIVE closure of `default`, since a
# default feature that enables another already reaches it through gate 3.
#
# Usage:
#   nondefault-features-gate.sh            # every such member (the sweep)
#   nondefault-features-gate.sh pkg [pkg…] # only these (the pre-push shape)
set -uo pipefail

# Tier 2: checked LIB-ONLY, because some test target of theirs does not survive
# every feature being on at once. Populated by measurement, never by guess.
lib_only=""
# Tier 3: no all-features check at all.
#
# `wz` is the facade crate and it has NO all-features build, because a vendored
# dependency refuses one: `sce-rust-runtime` carries a `compile_error!` reading
# "`no_std` and `http-send` are mutually exclusive: tokio/reqwest are
# std-coupled" (SCE Protocol-Synthesis RFC §5.J.2). That is an upstream design
# statement, not a defect here.
#
# R2133 MEASURED three combinations before writing this row, so the next round
# does not repeat them — each `cargo check -p wz --all-targets`, each exit 101
# on that same `compile_error!`:
#   1. `--all-features`                                     (247 features)
#   2. all features minus the no_std/MCU half              (237: dropped
#      runtime-no-std, runtime-coop, platform-{bare-metal,freertos,zephyr},
#      preset-{cortex-m0-minimal,cortex-m4-default,mcu-extended,mcu-minimal},
#      session-lwip)
#   3. all features minus the REST bridge, the guard's OTHER named side
#      (245: dropped rest-http-bridge, rest-sse-subscribe)
# So it is not one or two features standing in the way, and hunting a fourth
# subset by hand is the arbitrary-threshold shape this project keeps refusing.
#
# ⚠ THE RESIDUE, stated rather than hidden: `wz`'s 247 non-default features are
# the LARGEST hole this gate leaves, and it leaves them entirely. The shape that
# would close it is the crate's OWN declared coherent combinations -- the
# `preset-*` features are exactly that -- checked one per preset instead of all
# at once. That is a different instrument and belongs to its own round.
excluded="wz"

cd "$(dirname "$0")/../../crates" || exit 1

# The crates that HAVE a non-default feature, straight from cargo metadata.
read -r -d '' derive_py <<'PY'
import json
import sys

meta = json.load(sys.stdin)
for pkg in sorted(meta["packages"], key=lambda p: p["name"]):
    feats = pkg["features"]
    reach, stack = set(), list(feats.get("default", []))
    while stack:
        name = stack.pop().split("/")[0].lstrip("?")
        if name in reach:
            continue
        reach.add(name)
        if name in feats:
            stack.extend(feats[name])
    if set(feats) - reach - {"default"}:
        print(pkg["name"])
PY

mapfile -t with_nondefault < <(cargo metadata --no-deps --format-version 1 2>/dev/null |
    python3 -c "$derive_py")
if [[ ${#with_nondefault[@]} -eq 0 ]]; then
    echo "  nondefault-features FAIL: cargo metadata named no crate with a" \
         "non-default feature. Either the derivation is dead or every feature" \
         "in this workspace is on by default; both make this gate sweep" \
         "nothing while reporting a pass." >&2
    exit 1
fi

if [[ $# -gt 0 ]]; then
    # The pre-push shape: intersect the caller's changed crates with the
    # derived set, so naming a crate that has no non-default feature is a
    # no-op rather than a wasted build.
    members=()
    for pkg in "$@"; do
        for cand in "${with_nondefault[@]}"; do
            [[ "$pkg" == "$cand" ]] && members+=("$pkg") && break
        done
    done
else
    members=("${with_nondefault[@]}")
fi

fail=0
checked=0
for pkg in "${members[@]}"; do
    [[ -n "$pkg" ]] || continue
    if [[ " $excluded " == *" $pkg "* ]]; then
        continue
    fi
    if [[ " $lib_only " == *" $pkg "* ]]; then
        mode="lib-only"
        args=(check -p "$pkg" --all-features --quiet)
    else
        mode="all-targets"
        args=(check -p "$pkg" --all-features --all-targets --quiet)
    fi
    checked=$((checked + 1))
    if ! cargo "${args[@]}" >/dev/null 2>&1; then
        echo "  nondefault-features FAIL: $pkg does not compile with all of its" \
             "features on ($mode). This is code no local gate hands to rustc —" \
             "gate 3 builds default features only — so fix it, or move the crate" \
             "to a named tier in scripts/lib/nondefault-features-gate.sh and say" \
             "why."
        fail=1
    fi
done

# A tier row naming a crate that is no longer in the derived set is a row
# nobody is reading, and an exclusion that outlives its reason can silently
# re-attach to a crate that later gains a non-default feature. Only checkable
# on the SWEEP, exactly as the sibling gate's tier audit is.
if [[ $# -eq 0 ]]; then
    for named in $lib_only $excluded; do
        found=0
        for m in "${with_nondefault[@]}"; do
            [[ "$m" == "$named" ]] && found=1 && break
        done
        if [[ $found -eq 0 ]]; then
            echo "  nondefault-features FAIL: the tier list names $named, which has" \
                 "no non-default feature (or is not a member) — drop the row"
            fail=1
        fi
    done
fi

# A population of zero is the failure mode this project keeps meeting: a filter
# that matches nothing exits 0 and reads as a pass. On a SUBSET run zero is
# legitimate — the push may have touched only crates whose features are all on
# by default — so it is reported rather than failed, and the sweep above is
# what guarantees the derived set itself is non-empty.
if [[ $checked -eq 0 ]]; then
    echo "  nondefault-features: no changed crate has a non-default feature"
    exit $fail
fi

[[ $fail -eq 0 ]] && echo "  nondefault-features: $checked crate(s) compile with all features on" \
    "(of ${#with_nondefault[@]} with any non-default feature)"
exit $fail
