#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R2451 (no register item) — RUN the oracle that keeps a tracked capture a
# function of the encoders that emitted it.
#
# Answers item 699 of the unregistered register, which lives OUTSIDE this
# repository -- the reason the citation above reads "no register item", the
# same position `capi_c_abi_pin.py` records for item 634. The item is named in
# full here so a reader grepping for it lands on this file.
#
# ⚠ R2453 (item 700) — this line said `R2451 (open-debt item 699)`, which
# `gate_provenance_lint.py` does not admit: its item grammar takes `§…`, `N<nn>`,
# a store `debt-…` id, or `no register item`, and 699 has no store id (checked
# against `--list-inventory`, not assumed). Layer C0 went red on the commit that
# added this file and stayed red, which the round adding an unrelated door found
# because C0 is not a gate `pre-push` runs. Repaired here rather than deferred:
# a gate that cannot run grades nothing, and this one is the only oracle the
# tracked capture has.
#
# ## Why a gate of its own rather than the changed-crate test gate
#
# `captures/raweth-transport-messages.pcap` is graded by three `#[test]`s in
# `wz-capture`, but its bytes are produced by `wz_session_core::raweth_link`
# and by that crate's codecs. So the product and the oracle sit in DIFFERENT
# crates, which is exactly the shape open-debt item 687 measured: pre-push
# gate 3 runs `cargo test -p <crate>` for the crates the push's diff changes,
# so a push that edits the framing runs `wz-session-core`'s tests and never
# reaches the fixture that the framing defines. The same hole swallows a push
# that edits nothing but the `.pcap` itself — no crate directory moved, so no
# crate is tested, and a hand-edited capture would sail through the one check
# that exists to catch exactly that.
#
# UNCONDITIONAL, on gate 2h's decision for the same reason: a leg that runs
# only when someone happened to touch the right directory is the shape the
# item is about. MEASURED on this host: 0.3s with nothing to rebuild, and 6s
# when `wz-capture` and the two crates under it have to be recompiled — which
# is a push that touched them, and therefore a push gate 3 was going to spend
# that build on anyway.
#
# Hosted CI needs nothing added. These are plain default-feature lib tests, so
# Layer C1's `cargo test --workspace` already runs them; this gate is about
# WHEN, not about whether they exist anywhere.
#
# ## The set is pinned, not the count
#
# A count is satisfied by any three tests, including three that no longer
# grade the capture. Each expected name is required to have reported `ok` by
# name, and the gate PRINTS what it matched — because the failure this
# workspace pays for repeatedly is a filter that matched nothing while
# `cargo test` exited 0, and a silent pass is indistinguishable from a leg
# that never ran.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# The oracle set. A rename here without a rename there is the failure mode
# this list exists to make loud.
EXPECTED=(
    the_tracked_raweth_capture_is_byte_identical_to_what_wz_emits
    the_tracked_raweth_capture_carries_both_header_widths
    the_tracked_raweth_capture_reaches_the_consumer_surface
)

# The filter, and the crate whose suite hosts them.
CRATE="wz-capture"
FILTER="raweth_capture"

# Grade a `cargo test` transcript against EXPECTED. Separated from the run so
# `--selftest` can drive it over transcripts that never came from cargo, which
# is the only way to show this gate can still fail.
grade_transcript() {
    local transcript="$1" missing=0 name
    for name in "${EXPECTED[@]}"; do
        if grep -qE "^test [A-Za-z0-9_:]*${name} \.\.\. ok$" "$transcript"; then
            echo "  capture-provenance: ok    ${name}"
        else
            echo "  capture-provenance: MISSING or NOT ok    ${name}" >&2
            missing=$((missing + 1))
        fi
    done
    if [[ $missing -ne 0 ]]; then
        echo "  capture-provenance: ${missing} of ${#EXPECTED[@]} oracle(s) did not report ok" >&2
        return 1
    fi
    echo "  capture-provenance: ${#EXPECTED[@]} of ${#EXPECTED[@]} oracle(s) reported ok"
    return 0
}

selftest() {
    local tmp rc
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN

    # A transcript in which every expected name reported ok must PASS.
    : >"$tmp/all-ok"
    for name in "${EXPECTED[@]}"; do
        echo "test raweth_capture_fixture::${name} ... ok" >>"$tmp/all-ok"
    done
    if ! grade_transcript "$tmp/all-ok" >/dev/null 2>&1; then
        echo "capture-provenance SELFTEST: a transcript with every oracle ok was rejected" >&2
        return 1
    fi

    # One name FAILED instead of ok must be caught. This is the shape a real
    # red arrives in.
    sed "s/${EXPECTED[0]} \.\.\. ok/${EXPECTED[0]} ... FAILED/" \
        "$tmp/all-ok" >"$tmp/one-failed"
    grade_transcript "$tmp/one-failed" >/dev/null 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "capture-provenance SELFTEST: a FAILED oracle was read as a pass" >&2
        return 1
    fi

    # One name ABSENT must be caught — the rename case, which is the reason
    # the set is pinned rather than the count.
    grep -v "${EXPECTED[0]}" "$tmp/all-ok" >"$tmp/one-absent"
    grade_transcript "$tmp/one-absent" >/dev/null 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "capture-provenance SELFTEST: an ABSENT oracle was read as a pass" >&2
        return 1
    fi

    # An EMPTY transcript — what a filter that matched nothing leaves behind —
    # must be caught. The whole point.
    : >"$tmp/empty"
    grade_transcript "$tmp/empty" >/dev/null 2>&1
    rc=$?
    if [[ $rc -eq 0 ]]; then
        echo "capture-provenance SELFTEST: an empty transcript was read as a pass" >&2
        return 1
    fi

    echo "capture-provenance SELFTEST: 4 arm(s) of 4 — all-ok passes; FAILED, absent and empty each refused"
    return 0
}

case "${1-}" in
    --selftest)
        selftest
        exit $?
        ;;
    "") ;;
    *)
        echo "capture_provenance_gate.sh: unknown argument '$1'" >&2
        echo "  usage: capture_provenance_gate.sh [--selftest]" >&2
        exit 2
        ;;
esac

log="$(mktemp)"
trap 'rm -f "$log"' EXIT
(cd "$REPO_ROOT/crates" && cargo test -p "$CRATE" --lib "$FILTER") >"$log" 2>&1
run_rc=$?
if [[ $run_rc -ne 0 ]]; then
    echo "  capture-provenance: \`cargo test -p ${CRATE} --lib ${FILTER}\` exited ${run_rc}" >&2
    tail -40 "$log" >&2
    exit 1
fi
grade_transcript "$log"
