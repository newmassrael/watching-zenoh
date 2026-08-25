#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R311y821 (no register item) — the REDUCED-FEATURE-COMBINATION gate. The debt
# it closes is item 79 in the UNREGISTERED set, which has no store `debt-` id.
#
# ## The class, and why it needed a gate
#
# Nothing local builds a SHRUNKEN feature combination of a changed crate.
# `cargo clippy --all-features` is structurally blind to a cfg-gated-import
# defect — the feature is ON, so the import resolves — and the crate's own
# default-feature test run is blind for the same reason. The class fired twice:
#
#   R311y809 — a `SocketAddr` import gated on `transport-link-udp` behind an
#   ungated signature. Caught only because pre-push's doc-link gate happened to
#   build a LINKING crate in a different combination: detection existed as
#   another gate's side effect.
#
#   R311y811 — a module ungated while every test inside it stayed gated, so the
#   bare combination compiled ZERO tests and the only symptom was one unused
#   `use super::*` under `-D warnings`. No accident rescued that one; it reached
#   origin, and hosted Layer C1o (a keyexpr lane) was the only host lane that
#   compiles this crate's lib tests with `--no-default-features`.
#
# ## Why a pinned SET rather than "all crates must pass"
#
# R311y821 MEASURED the cost the debt recorded as unknown: of 53 workspace
# members, 49 are already clean under `--no-default-features --all-targets
# -- -D warnings`, and the 4 that are not fail for ONE reason — their own TEST
# targets reach a facade the bare build removes (`encode_to_vec`, the
# alloc-backed sink; `wz::runtime_tokio` for the demo binary). That is a
# property of those crates' test surface, not a defect, so they are named
# exclusions rather than a reason to abandon the gate. Three of the four are
# clean LIB-ONLY and are checked that way, which keeps their production code
# under the gate; only `wz-ap-demo` is out entirely, because bare removes the
# runtime its whole binary is about.
#
# The SET is pinned, not counted: a crate that starts failing is named, and a
# NEW crate is refused until it is placed in one of the three tiers. That is
# this project's own rule — pin the set, not the count.
#
# Usage:
#   reduced-features-gate.sh            # every workspace member (the sweep)
#   reduced-features-gate.sh pkg [pkg…] # only these (the pre-push shape)
set -uo pipefail

# Tier 2: bare is checked LIB-ONLY. Their test targets need the alloc-backed
# encode facade that `--no-default-features` removes.
lib_only="wz-codecs wz-ap-demo-app wz-switchboard-example"
# Tier 3: no bare check at all. `wz-ap-demo` is a binary whose every module
# reaches `wz::runtime_tokio`; bare deletes the runtime, so there is no
# reduced combination of it to grade.
excluded="wz-ap-demo"

cd "$(dirname "$0")/../../crates" || exit 1

if [[ $# -gt 0 ]]; then
    members=("$@")
else
    mapfile -t members < <(cargo metadata --no-deps --format-version 1 2>/dev/null |
        python3 -c "import sys,json;[print(p['name']) for p in sorted(json.load(sys.stdin)['packages'], key=lambda x: x['name'])]")
    if [[ ${#members[@]} -eq 0 ]]; then
        echo "  reduced-features FAIL: cargo metadata listed no workspace member" >&2
        exit 1
    fi
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
        args=(clippy -p "$pkg" --no-default-features --quiet)
    else
        mode="all-targets"
        args=(clippy -p "$pkg" --no-default-features --all-targets --quiet)
    fi
    checked=$((checked + 1))
    if ! cargo "${args[@]}" -- -D warnings >/dev/null 2>&1; then
        echo "  reduced-features FAIL: $pkg does not build clean under" \
             "--no-default-features ($mode). Either fix the reduced combination —" \
             "usually a cfg-gated import behind an ungated signature, or a test" \
             "module whose every member is gated — or move the crate to a named" \
             "tier in scripts/lib/reduced-features-gate.sh and say why."
        fail=1
    fi
done

# A tier row naming a crate the workspace no longer has is a row nobody is
# reading — and worse than dead weight here, because an exclusion that outlives
# its crate can later re-attach to a NEW crate of the same name and silently
# exempt it. Only checkable on the SWEEP: a subset run legitimately names none
# of them. Same rule the literal-key gate and the C1bz budget already follow.
if [[ $# -eq 0 ]]; then
    for named in $lib_only $excluded; do
        found=0
        for m in "${members[@]}"; do
            [[ "$m" == "$named" ]] && found=1 && break
        done
        if [[ $found -eq 0 ]]; then
            echo "  reduced-features FAIL: the tier list names $named, which is not a" \
                 "workspace member — drop the row"
            fail=1
        fi
    done
fi

# A population of zero is the failure mode this project keeps meeting: a filter
# that matches nothing exits 0 and reads as a pass.
if [[ $checked -eq 0 ]]; then
    echo "  reduced-features: nothing to check (all named crates are excluded)"
    exit $fail
fi

[[ $fail -eq 0 ]] && echo "  reduced-features: $checked crate(s) build clean with default features off"
exit $fail
