#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-watching-zenoh-NonCommercial-1.0 OR LicenseRef-watching-zenoh-Commercial
# SPDX-FileCopyrightText: Copyright (c) 2026 newmassrael
#
# R1994 (debt-sce-codegen-provenance)
#
# The sce-codegen ORACLE gate — shared by every shell consumer of
# `vendor/sce/target/release/sce-codegen`.
#
# It ANSWERS FOR that item without closing it: the sce-codegen instance is
# closed and gated here, and the item stays open for the untracked oracles that
# still carry no provenance record at all (`target/zenohd`,
# `target/zenoh-pico-cli`, the capture fixtures) and for
# `binary_freshness_lint.py`, which grades the sibling class by mtime — the same
# wrong question one layer over.
#
# ## What it grades
#
# WHICH vendor/sce revision the built binary was built FROM — not whether it
# exists, and not when it was built. Both of those were asked before, and both
# gave wrong answers:
#
#   EXISTENCE.  Layer B and Layer B2 each opened with `[[ ! -x <bin> ]] && SKIP`.
#   A lane whose oracle is an untracked build product therefore reports a
#   pass-shaped SKIP on any host that does not carry it. `bx` prunes
#   `vendor/sce/target` after every remote run, so that host is the normal case,
#   not the exotic one.
#
#   MTIME.  R114 added a real freshness gate after a green local pre-push went
#   red on hosted CI (msg_del/query/request mismatches traced to a binary built
#   against the pre-R112 pin). It compares the binary's mtime to the pin
#   commit's author time and rebuilds when the binary is older. That gate is
#   correct in the developer loop it was written for and wrong in general:
#   mtime answers *when* the binary was built, never *what from*. Move the pin
#   BACKWARDS — a rebase, a cherry-pick, a revert to an older SCE revision —
#   and a binary built yesterday is "newer" than a pin committed last week, so
#   the stale binary passes. Any copy that resets mtimes (rsync, tar, a fresh
#   container layer) defeats it the same way.
#
#   It also lived in ONE lane. Layer B2's own comment outsourced the question —
#   "In a full run-ci, Layer B builds + freshness-checks the binary before this
#   lane" — which holds for a full sweep and for nothing else. `--layer B2`
#   alone had no check at all.
#
# ## The measured failure this replaces
#
# 2026-08-22, this round. The SCE pin moved 0ac56f1a45 -> 6399fad49c, whose
# templates introduce a `host_invoker` filter. `--layer B2` ran on a build host
# carrying a binary from an older pin and failed with
#
#     unknown filter: filter host_invoker is unknown (in entry_exit_actions.rs.jinja2:462)
#
# which names a template, a filter and a line number, and not one of them is the
# defect. The tree was fine; the oracle was from a different tree. The sibling
# class is already written down at scripts/lib/binary_freshness_lint.py: R311y774
# tested a feature against a demo binary predating it and attributed the red to a
# feature-closure defect that did not exist, and R311y776 retracted the whole
# diagnosis. A stale oracle does not report "stale" — it reports a plausible
# wrong answer somewhere else.
#
# ## The provenance stamp
#
# `scripts/build-sce.sh` writes `<bin dir>/.sce-codegen.pin` after a SUCCESSFUL
# build, holding the exact source state it built from. Consumers recompute that
# same token from the tree and compare STRINGS. No clock is involved, so none of
# the mtime defeats above apply.
#
# The token is `<full-rev>-<dirty-digest>`, not the rev alone, because
# `vendor/sce` is a working checkout: an uncommitted template edit changes what
# the binary must be, while HEAD stays put. When the checkout is clean the digest
# is the digest of empty input and the token is stable across machines.
#
# ## Arming
#
# `WZ_SCE_ORACLE_REQUIRE=1` turns "cannot establish the oracle" from a SKIP into
# a hard failure. Hosted CI arms it: there the submodule and the toolchain are
# always present, so an unavailable oracle is a broken runner rather than a
# developer without libxml2. This mirrors the WZ_*_REQUIRE convention Layers D
# and F already use for python3.
#
# This file is PURE FUNCTION DEFINITIONS. Sourcing it must stay side-effect
# free — run-ci.sh and the wrapper scripts source it, and a sourced file that
# builds is how a wrapper starts compiling before it has parsed its arguments.
# Do not add top-level statements beyond these constants.
#
# R2326 (unregistered open-debt item 10) — the token construction moved to
# `scripts/lib/vendored-oracle.sh` when zenoh-pico became a second oracle
# needing the identical string. This file keeps its three public names and
# delegates: a second implementation of one token is the open-debt item 47
# shape, and the Rust side already has to reproduce it byte for byte, which is
# copy number two and the ceiling.
# shellcheck source=scripts/lib/vendored-oracle.sh
source "$(dirname "${BASH_SOURCE[0]}")/vendored-oracle.sh"
# `wz_artifact_dir`: where a product of a tree path is (the rule, scripts/lib/artifact-root.sh).
# shellcheck source=scripts/lib/artifact-root.sh
source "$(dirname "${BASH_SOURCE[0]}")/artifact-root.sh"
# `wz_build_evidence`: what a failed rebuild prints (scripts/lib/build-evidence.sh).
# shellcheck source=scripts/lib/build-evidence.sh
source "$(dirname "${BASH_SOURCE[0]}")/build-evidence.sh"

WZ_SCE_DIR="vendor/sce"
WZ_SCE_CODEGEN_BIN="vendor/sce/target/release/sce-codegen"
WZ_SCE_CODEGEN_STAMP="vendor/sce/target/release/.sce-codegen.pin"
# What sce-codegen prints on stderr when it parsed a document without validating
# it. The Rust door carries the same text (XSD_NOT_VALIDATED in
# crates/wz-codegen-build/src/spawn.rs); scripts/lib/sce_codegen_spawn_lint.py
# holds the two and the generator's own wording to one another.
WZ_SCE_XSD_NOT_VALIDATED="XSD schema validation did not run"

# sce_codegen_spawn <binary> <sce-dir> <stderr-file> <arg>...
#
# THE ONE SHELL DOOR THROUGH WHICH THIS TREE RUNS sce-codegen; the Rust door is
# `SceCodegen` in crates/wz-codegen-build. sce-codegen finds its workspace, its
# Jinja2 templates and its XSD schemas by looking around the machine when it is
# not told, and each guess has missed on some build host while the tree passed
# where it was written. So all three are named here, derived from <sce-dir>, and
# scripts/lib/sce_codegen_spawn_lint.py refuses a spawn written anywhere else.
# A caller that sets SCE_TEMPLATE_DIR or SCE_SCHEMAS_DIR still points elsewhere;
# an empty value counts as unset, as it does in the Rust door.
#
# The XSD half is why this returns codes of its own. When the schema is missing,
# or the binary was built without the `xsd` feature, sce-codegen warns, emits
# from a document whose sce: attributes nobody checked, and exits 0. A warning
# in a log is not a verdict, so that run is refused here.
#
# Standard output is the caller's; standard error goes to <stderr-file>, which
# also receives the reason for a refusal.
#
#   n    sce-codegen's own exit status, when it ran and failed
#   0    it ran, succeeded and validated
#   125  refused before running: the template directory or the schema is not
#        where it is named
#   126  it exited 0 but said that XSD validation did not run
sce_codegen_spawn() {
    local bin="$1" sce="$2" errf="$3"
    shift 3
    local templates="${SCE_TEMPLATE_DIR:-$sce/tools/codegen/templates}"
    local schemas="${SCE_SCHEMAS_DIR:-$sce/schemas}"
    if [[ ! -d "$templates" ]]; then
        echo "sce_codegen_spawn: no template directory at $templates" >"$errf"
        return 125
    fi
    if [[ ! -f "$schemas/sce-forge.xsd" ]]; then
        echo "sce_codegen_spawn: no XSD schema at $schemas/sce-forge.xsd; sce-codegen would emit without validating" >"$errf"
        return 125
    fi
    local rc=0
    SCE_TEMPLATE_DIR="$templates" SCE_SCHEMAS_DIR="$schemas" \
        "$bin" --workspace-root "$sce" "$@" 2>"$errf" || rc=$?
    if [[ $rc -eq 0 ]] && grep -qF "$WZ_SCE_XSD_NOT_VALIDATED" "$errf"; then
        echo "sce_codegen_spawn: sce-codegen exited 0 without validating against the XSD" >>"$errf"
        return 126
    fi
    return "$rc"
}

# sce_codegen_source_token <sce-dir>
#
# Print the token identifying the SCE source state a build would consume, or
# print nothing and return 1 when it cannot be established (no checkout, no git).
#
# The dirty digest folds BOTH the untracked/modified listing and the tracked
# diff, for the same reason bx's tree fingerprint does: `git status --porcelain`
# alone cannot see a change that leaves the path list identical, and `git diff`
# alone cannot see a new untracked template.
#
# The digest is computed by `git hash-object`, deliberately, and not by md5sum
# or sha256sum. GIT IS THE ONLY DEPENDENCY THIS TOKEN HAS, which is what lets
# the Rust side (crates/wz-codegen-build) recompute the identical string with
# two subprocess calls and no hashing crate. A token only one language can
# compute is a token the other language has to trust, and the whole point here
# is that nothing trusts the binary's own claim about itself.
#
# `target/` IS EXCLUDED, and that is load-bearing rather than tidiness. The
# token must describe the SOURCE state that determines the binary; `target/`
# holds the binary and the stamp itself. Include it and the record changes the
# thing it records — writing the stamp makes the checkout dirty, which moves the
# token, so the stamp can never match and every consumer rebuilds or refuses
# forever. MEASURED: crates/wz-codegen-build/tests/provenance.rs caught exactly
# this, on a fixture whose `target/` was not gitignored. That today's
# vendor/sce happens to ignore `target/` is a fact about upstream's .gitignore,
# not a property of this gate, and it is not something to depend on.
sce_codegen_source_token() {
    vendored_oracle_git_token "${1:-$WZ_SCE_DIR}"
}

# sce_codegen_stamped_token [stamp-path]
#
# Print the token the built binary carries, or nothing when unstamped. An
# unstamped binary is treated as UNKNOWN provenance and therefore as stale:
# every binary this repo builds has been stamped since this file landed, so an
# unstamped one predates the gate and is exactly the case it exists to catch.
sce_codegen_stamped_token() {
    vendored_oracle_stamped_token "${1:-$WZ_SCE_CODEGEN_STAMP}"
}

# sce_codegen_write_stamp <sce-dir> <stamp-path>
#
# Record the source state a just-completed build consumed. Called by
# build-sce.sh AFTER cargo reports success — never before, so a failed build
# cannot leave behind a stamp asserting freshness it does not have.
sce_codegen_write_stamp() {
    local dir="$1" stamp="$2"
    # No git to read: leave the binary UNSTAMPED rather than stamp it with a
    # guess — which is what an empty token asks the writer to do. Unstamped
    # reads as stale, which is the safe direction.
    vendored_oracle_write_stamp "$stamp" "$(sce_codegen_source_token "$dir" || true)"
}

# sce_codegen_ensure <label>
#
# Bring the oracle to the revision this tree pins, rebuilding when it is absent
# or was built from anything else. Prints what it did on the caller's stdout.
#
#   0  the binary exists and provably matches the pinned source state
#   1  HARD FAIL — the rebuild failed, or succeeded and still does not match
#   2  UNAVAILABLE — the oracle cannot be established here (no submodule, no
#      cargo, no git). The caller may SKIP, unless WZ_SCE_ORACLE_REQUIRE=1, in
#      which case this returns 1 instead and never 2.
sce_codegen_ensure() {
    local label="${1:-sce-codegen}"
    # Spelled as an `if` and not `[[ ... ]] && x`: an AND-list whose test fails
    # returns 1, and this file is sourced by callers that run under `set -e`.
    local unavailable=2
    if [[ "${WZ_SCE_ORACLE_REQUIRE:-0}" == "1" ]]; then
        unavailable=1
    fi

    local want
    if ! want="$(sce_codegen_source_token "$WZ_SCE_DIR")"; then
        echo "$label: sce-codegen oracle UNAVAILABLE (no readable $WZ_SCE_DIR checkout; run: git submodule update --init $WZ_SCE_DIR)"
        return "$unavailable"
    fi

    local have=""
    if [[ -x "$WZ_SCE_CODEGEN_BIN" ]]; then
        have="$(sce_codegen_stamped_token "$WZ_SCE_CODEGEN_STAMP" || true)"
        if [[ "$have" == "$want" ]]; then
            return 0
        fi
    fi

    # Say WHICH of the three states we are in before rebuilding, so a log read
    # later can tell "never built here" from "built from something else" — the
    # R311y889 rule that a skip or a repair must carry its reason.
    if [[ ! -x "$WZ_SCE_CODEGEN_BIN" ]]; then
        echo "$label: sce-codegen absent; building at ${want%%-*}"
    elif [[ -z "$have" ]]; then
        echo "$label: sce-codegen carries no provenance stamp (predates the oracle gate); rebuilding at ${want%%-*}"
    else
        echo "$label: sce-codegen was built from ${have%%-*}, tree pins ${want%%-*}; rebuilding"
    fi

    if ! command -v cargo >/dev/null 2>&1; then
        echo "$label: sce-codegen oracle UNAVAILABLE (cargo not on PATH; cannot build it)"
        return "$unavailable"
    fi

    # A log is a product: under the artifact root (scripts/lib/artifact-root.sh).
    local log
    log="${RUNCI_LOG_DIR:-$(wz_artifact_dir crates/target/run-ci-logs)}/sce-codegen-oracle-rebuild.log"
    mkdir -p "$(dirname "$log")" 2>/dev/null || true
    if ! bash scripts/build-sce.sh >"$log" 2>&1; then
        # KEEP WHAT IT SAID (R311y756 / R311y889): a build that failed silently
        # costs a second full build to learn anything.
        echo "$label: sce-codegen rebuild FAILED" >&2
        wz_build_evidence "$log" 40 >&2
        return 1
    fi

    have="$(sce_codegen_stamped_token "$WZ_SCE_CODEGEN_STAMP" || true)"
    if [[ "$have" != "$want" ]]; then
        # A rebuild that reports success and still does not match means the
        # stamp and the build disagree about what was built. That is a defect in
        # this gate or in build-sce.sh, and it must never degrade to a pass.
        echo "$label: sce-codegen rebuilt but provenance still does not match" >&2
        echo "  want: $want" >&2
        echo "  have: ${have:-<unstamped>}" >&2
        return 1
    fi
    return 0
}
